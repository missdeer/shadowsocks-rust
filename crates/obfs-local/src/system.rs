// SPDX-License-Identifier: GPL-3.0-or-later

use std::{io, net::SocketAddr};

#[cfg(unix)]
use socket2::SockRef;
use tokio::net::TcpSocket;

use crate::{config::Config, relay::Transport};

pub async fn connect(remote: SocketAddr, config: &Config) -> io::Result<Box<dyn Transport>> {
    let socket = make_socket(remote, config)?;
    socket.set_nodelay(true)?;
    #[cfg(target_os = "linux")]
    if let Some(interface) = &config.interface {
        // Like simple-obfs, interface failures are logged but do not prevent
        // the connection from being attempted.
        if let Err(error) = SockRef::from(&socket).bind_device(Some(interface.as_bytes())) {
            eprintln!("[obfs-local] failed to bind interface: {error}");
        }
    }
    #[cfg(any(
        target_os = "linux",
        target_os = "windows",
        target_os = "macos",
        target_os = "freebsd"
    ))]
    if config.fast_open {
        return Ok(Box::new(
            tokio_tfo::TfoStream::connect_with_socket(socket, remote).await?,
        ));
    }
    Ok(Box::new(socket.connect(remote).await?))
}

fn make_socket(remote: SocketAddr, config: &Config) -> io::Result<TcpSocket> {
    #[cfg(target_os = "linux")]
    if config.mptcp {
        use socket2::{Domain, Protocol, Socket, Type};
        use std::os::fd::{FromRawFd, IntoRawFd};
        match Socket::new(
            Domain::for_address(remote),
            Type::STREAM,
            Some(Protocol::from(libc::IPPROTO_MPTCP)),
        ) {
            Ok(socket) => {
                socket.set_nonblocking(true)?;
                // SAFETY: ownership transfers to TcpSocket exactly once.
                return Ok(unsafe { TcpSocket::from_raw_fd(socket.into_raw_fd()) });
            }
            Err(error) => eprintln!("[obfs-local] MPTCP unavailable, using TCP: {error}"),
        }
    }
    let _ = config;
    if remote.is_ipv4() {
        TcpSocket::new_v4()
    } else {
        TcpSocket::new_v6()
    }
}

pub async fn bind(config: &Config) -> io::Result<tokio::net::TcpListener> {
    let addresses = tokio::net::lookup_host((config.local_host.as_str(), config.local_port)).await?;
    let mut error = io::Error::other("local address resolved to no addresses");
    for address in addresses {
        let socket = if address.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };
        socket.set_reuseaddr(true)?;
        #[cfg(unix)]
        let _ = SockRef::from(&socket).set_reuse_port(true);
        match socket.bind(address) {
            Ok(()) => return socket.listen(1024),
            Err(current) => error = current,
        }
    }
    Err(error)
}

pub async fn shutdown_signal() -> io::Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut interrupt = signal(SignalKind::interrupt())?;
        let mut terminate = signal(SignalKind::terminate())?;
        let mut user = signal(SignalKind::user_defined1())?;
        tokio::select! {
            _ = interrupt.recv() => {},
            _ = terminate.recv() => {},
            _ = user.recv() => {},
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await
    }
}

/// Unix SIP003 children stop when their launching process disappears.
pub async fn parent_exit() {
    #[cfg(unix)]
    {
        // SAFETY: getppid has no preconditions.
        let parent = unsafe { libc::getppid() };
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            if unsafe { libc::getppid() } != parent {
                return;
            }
        }
    }
    #[cfg(not(unix))]
    std::future::pending::<()>().await;
}

/// Must run before Tokio is initialized: daemonization forks the process.
pub fn prepare(config: &Config) -> io::Result<()> {
    #[cfg(unix)]
    {
        if let Some(nofile) = config.nofile.filter(|value| *value > 1024) {
            let limit = libc::rlimit {
                rlim_cur: nofile as libc::rlim_t,
                rlim_max: nofile as libc::rlim_t,
            };
            // SAFETY: pointer references a valid rlimit for the duration of the call.
            if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) } != 0 {
                eprintln!("[obfs-local] failed to set NOFILE: {}", io::Error::last_os_error());
            }
        }
        if let Some(path) = &config.pid_file {
            // Open before fork so an unwritable PID path fails in the parent.
            use std::io::Write;
            let mut pid_file = std::fs::File::create(path)?;
            // SAFETY: called before threads/runtime exist; the parent exits.
            let pid = unsafe { libc::fork() };
            if pid < 0 {
                return Err(io::Error::last_os_error());
            }
            if pid > 0 {
                write!(pid_file, "{pid}")?;
                std::process::exit(0);
            }
            // SAFETY: called in the newly forked child.
            if unsafe { libc::setsid() } < 0 {
                return Err(io::Error::last_os_error());
            }
            unsafe { libc::umask(0) };
            std::env::set_current_dir("/")?;
            let null = std::fs::File::open("/dev/null")?;
            use std::os::fd::AsRawFd;
            for fd in [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
                // SAFETY: duplicates a valid file descriptor onto standard streams.
                if unsafe { libc::dup2(null.as_raw_fd(), fd) } < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
        }
    }
    #[cfg(not(unix))]
    {
        // simple-obfs's MinGW implementation ignores -f/-a/-n/-i.
        let _ = config;
    }
    Ok(())
}

pub fn switch_user(config: &Config) -> io::Result<()> {
    #[cfg(unix)]
    if let Some(user) = &config.user {
        use std::ffi::CString;
        let name = CString::new(user.as_str()).map_err(|_| io::Error::other("user contains NUL"))?;
        // SAFETY: valid C string; called on the single runtime thread before serving.
        let entry = unsafe { libc::getpwnam(name.as_ptr()) };
        if entry.is_null() {
            return Err(io::Error::other("unknown user"));
        }
        let (uid, gid) = unsafe { ((*entry).pw_uid, (*entry).pw_gid) };
        // Drop supplementary groups before the primary group and user IDs.
        if unsafe { libc::initgroups(name.as_ptr(), gid) } != 0
            || unsafe { libc::setgid(gid) } != 0
            || unsafe { libc::setuid(uid) } != 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    let _ = config;
    Ok(())
}
