// SPDX-License-Identifier: GPL-3.0-or-later

use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use rand::RngExt;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, lookup_host},
    sync::watch,
    task::JoinSet,
    time::{Instant, sleep_until, timeout},
};

use crate::{
    config::Config,
    protocol::{Decoder, Encoder},
    system,
};

pub trait Transport: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Transport for T {}

/// Resolve one address per remote, as the C client does at startup. Remote
/// selection is randomized per connection; IPv6 preference applies to DNS.
pub async fn resolve_remotes(config: &Config) -> io::Result<Vec<SocketAddr>> {
    let mut remotes = Vec::with_capacity(config.remotes.len());
    for remote in &config.remotes {
        let mut addresses: Vec<_> = lookup_host((remote.host.as_str(), remote.port)).await?.collect();
        addresses.sort_by_key(|addr| addr.is_ipv6() != config.ipv6_first);
        remotes.push(
            addresses
                .into_iter()
                .next()
                .ok_or_else(|| io::Error::other("remote resolved to no addresses"))?,
        );
    }
    Ok(remotes)
}

pub async fn serve(listener: TcpListener, config: Arc<Config>, remotes: Vec<SocketAddr>) -> io::Result<()> {
    let remotes = Arc::new(remotes);
    let mut tasks = JoinSet::new();
    let shutdown = system::shutdown_signal();
    tokio::pin!(shutdown);
    let parent = system::parent_exit();
    tokio::pin!(parent);
    loop {
        tokio::select! {
            _ = &mut parent => return Ok(()),
            result = &mut shutdown => {
                result?;
                tasks.abort_all();
                while tasks.join_next().await.is_some() {}
                return Ok(());
            }
            result = listener.accept() => {
                let (local, _) = result?;
                let config = config.clone();
                let remote = remotes[rand::rng().random_range(0..remotes.len())];
                tasks.spawn(async move {
                    if let Err(error) = relay(local, remote, &config).await
                        && config.verbose
                    {
                        // Avoid including provider addresses or plugin options in logs.
                        eprintln!("[obfs-local] connection error: {error}");
                    }
                });
            }
            Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                if let Err(error) = result {
                    eprintln!("[obfs-local] connection task failed: {error}");
                }
            }
        }
    }
}

pub async fn relay(mut local: TcpStream, remote: SocketAddr, config: &Config) -> io::Result<()> {
    local.set_nodelay(true)?;
    // Do not dial upstream for empty SIP003 readiness probes.
    let mut first = [0u8; 2048];
    let count = local.read(&mut first).await?;
    if count == 0 {
        return Ok(());
    }
    let mut encoder = Encoder::new(config.parameters.clone());
    let first = encoder.encode(&first[..count])?;
    let connect_timeout = config.timeout.min(Duration::from_secs(10));
    let upstream = timeout(connect_timeout, async {
        let mut stream = system::connect(remote, config).await?;
        // TFO may postpone the actual connection until the first write.
        stream.write_all(&first).await?;
        stream.flush().await?;
        Ok::<_, io::Error>(stream)
    })
    .await
    .map_err(|_| timed_out())??;
    let (mut local_read, mut local_write) = local.into_split();
    let (mut remote_read, mut remote_write) = tokio::io::split(upstream);
    let (activity, mut activity_rx) = watch::channel(Instant::now());
    let outgoing = async {
        let mut buffer = [0u8; 2048];
        loop {
            let count = local_read.read(&mut buffer).await?;
            if count == 0 {
                return remote_write.shutdown().await;
            }
            remote_write.write_all(&encoder.encode(&buffer[..count])?).await?;
        }
    };
    let incoming = async {
        let mut decoder = Decoder::new(config.parameters.mode);
        let mut buffer = [0u8; 2048];
        loop {
            let count = remote_read.read(&mut buffer).await?;
            if count == 0 {
                decoder.finish()?;
                return local_write.shutdown().await;
            }
            activity.send_replace(Instant::now());
            local_write.write_all(&decoder.decode(&buffer[..count])?).await?;
        }
    };
    let expiry = async {
        loop {
            let deadline = *activity_rx.borrow_and_update() + config.timeout;
            tokio::select! {
                _ = sleep_until(deadline) => return Err::<(), _>(timed_out()),
                result = activity_rx.changed() => {
                    if result.is_err() {
                        return Ok(());
                    }
                }
            }
        }
    };
    // A completed downstream closes the connection, matching the C client.
    // An upstream half-close still permits the server to finish its response.
    let transfer = async {
        tokio::pin!(outgoing, incoming);
        tokio::select! {
            result = &mut incoming => result,
            result = &mut outgoing => {
                result?;
                incoming.await
            }
        }
    };
    tokio::select! {
        result = transfer => result,
        result = expiry => result,
    }
}

fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "TCP connection timeout")
}
