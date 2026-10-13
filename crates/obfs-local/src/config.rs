// SPDX-License-Identifier: GPL-3.0-or-later
// Option names and precedence follow simple-obfs local.c / jconf.c.

use std::{collections::HashMap, fs, io, net::IpAddr, path::PathBuf, time::Duration};

use clap::{Arg, ArgAction, ArgMatches, Command};
use serde_json::Value;

use crate::protocol::{Mode, Parameters};

#[derive(Clone, Debug)]
pub struct Remote {
    pub host: String,
    pub port: u16,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub remotes: Vec<Remote>,
    pub local_host: String,
    pub local_port: u16,
    pub timeout: Duration,
    pub parameters: Parameters,
    pub ipv6_first: bool,
    pub verbose: bool,
    pub fast_open: bool,
    pub mptcp: bool,
    pub interface: Option<String>,
    pub user: Option<String>,
    pub pid_file: Option<PathBuf>,
    pub nofile: Option<u64>,
}

pub fn command() -> Command {
    let mut command = Command::new("obfs-local")
        .about("simple-obfs compatible HTTP/TLS client (Rust)")
        .version(env!("CARGO_PKG_VERSION"))
        .disable_version_flag(true)
        .args_override_self(true);
    for (name, short, help) in [
        (
            "server",
            's',
            "Host name or IP address of the remote server (repeatable)",
        ),
        ("server-port", 'p', "Remote server port"),
        ("local-port", 'l', "Local listening port"),
        ("timeout", 't', "Socket timeout in seconds (default: 600)"),
        ("interface", 'i', "Bind outbound sockets to this interface (Linux)"),
        ("config", 'c', "JSON configuration file"),
        ("local-address", 'b', "Local address (default: 127.0.0.1)"),
        ("user", 'a', "Run as another user (Unix)"),
        ("pid-file", 'f', "Daemonize and write PID file (Unix)"),
        ("nofile", 'n', "Maximum number of open files (Unix)"),
    ] {
        let arg = Arg::new(name).short(short).help(help).action(if name == "server" {
            ArgAction::Append
        } else {
            ArgAction::Set
        });
        command = command.arg(arg);
    }
    for (name, help) in [
        ("obfs", "Obfuscation mode: http or tls"),
        ("obfs-host", "Obfuscation hostname (default: cloudfront.net)"),
        ("obfs-uri", "HTTP path (default: /)"),
        ("http-method", "HTTP method (default: GET)"),
    ] {
        command = command.arg(Arg::new(name).long(name).help(help));
    }
    command
        .arg(
            Arg::new("verbose")
                .short('v')
                .action(ArgAction::SetTrue)
                .help("Verbose mode"),
        )
        .arg(
            Arg::new("ipv6-first")
                .short('6')
                .action(ArgAction::SetTrue)
                .help("Prefer IPv6 addresses"),
        )
        .arg(
            Arg::new("fast-open")
                .long("fast-open")
                .action(ArgAction::SetTrue)
                .help("Enable TCP Fast Open"),
        )
        .arg(
            Arg::new("mptcp")
                .long("mptcp")
                .action(ArgAction::SetTrue)
                .help("Enable Multipath TCP (Linux)"),
        )
}

impl Config {
    pub fn from_matches(matches: &ArgMatches, environment: &HashMap<String, String>) -> io::Result<Self> {
        let options = parse_plugin_options(environment.get("SS_PLUGIN_OPTIONS").map_or("", String::as_str))?;
        let selected = |arg: &str, option: &str| {
            matches
                .get_one::<String>(arg)
                .cloned()
                .or_else(|| options.get(option).cloned())
        };
        let document = match selected("config", "c") {
            Some(path) => {
                let data = fs::read(path)?;
                if data.len() >= 16 * 1024 {
                    return Err(invalid("configuration file must be smaller than 16 KiB"));
                }
                let document: Value = serde_json::from_slice(&data).map_err(io::Error::other)?;
                if !document.is_object() {
                    return Err(invalid("configuration must be a JSON object"));
                }
                document
            }
            None => Value::Object(Default::default()),
        };
        let field = |key: &str| -> io::Result<Option<String>> {
            match document.get(key) {
                None | Some(Value::Null) => Ok(None),
                Some(Value::String(value)) => Ok(Some(value.clone())),
                Some(Value::Number(value)) if value.is_u64() || value.is_i64() => Ok(Some(value.to_string())),
                _ => Err(invalid(&format!("{key} must be a string or integer"))),
            }
        };
        let value = |arg: &str, option: &str, json: &str| -> io::Result<Option<String>> {
            Ok(selected(arg, option).or(field(json)?))
        };
        let flag = |arg: &str, option: &str, json: &str| -> io::Result<bool> {
            let configured = match document.get(json) {
                None => false,
                Some(Value::Bool(value)) => *value,
                _ => return Err(invalid(&format!("{json} must be a boolean"))),
            };
            Ok(matches.get_flag(arg) || options.contains_key(option) || configured)
        };
        let mut hosts: Vec<String> = environment
            .get("SS_REMOTE_HOST")
            .into_iter()
            .flat_map(|value| value.split('|'))
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .collect();
        if let Some(servers) = matches.get_many::<String>("server") {
            hosts.extend(servers.cloned());
        }
        let mut from_array = false;
        if hosts.is_empty() {
            match document.get("server") {
                Some(Value::String(host)) => hosts.push(host.clone()),
                Some(Value::Array(servers)) => {
                    from_array = true;
                    for host in servers.iter().take(10) {
                        hosts.push(
                            host.as_str()
                                .ok_or_else(|| invalid("server array entries must be strings"))?
                                .to_owned(),
                        );
                    }
                }
                None => {}
                _ => return Err(invalid("server must be a string or array")),
            }
        }
        hosts.truncate(10);
        if hosts.is_empty() {
            return Err(invalid("remote server is required (-s or SS_REMOTE_HOST)"));
        }
        let remote_port = matches
            .get_one::<String>("server-port")
            .cloned()
            .or_else(|| environment.get("SS_REMOTE_PORT").cloned())
            .or(field("server_port")?)
            .ok_or_else(|| invalid("remote server port is required (-p or SS_REMOTE_PORT)"))?;
        let remote_port = parse_port(&remote_port, "server_port")?;
        let mut remotes = Vec::new();
        for host in hosts {
            let (host, port) = if from_array {
                split_address(&host, remote_port)?
            } else {
                (host, remote_port)
            };
            if host.is_empty() {
                return Err(invalid("server host cannot be empty"));
            }
            remotes.push(Remote { host, port });
        }
        let local_host = matches
            .get_one::<String>("local-address")
            .cloned()
            .or_else(|| environment.get("SS_LOCAL_HOST").cloned())
            .or(field("local_address")?)
            .unwrap_or_else(|| "127.0.0.1".to_owned());
        let local_port = matches
            .get_one::<String>("local-port")
            .cloned()
            .or_else(|| environment.get("SS_LOCAL_PORT").cloned())
            .or(field("local_port")?)
            .ok_or_else(|| invalid("local port is required (-l or SS_LOCAL_PORT)"))?;
        let timeout = value("timeout", "t", "timeout")?.unwrap_or_else(|| "600".to_owned());
        let timeout = timeout
            .parse::<u64>()
            .map_err(|_| invalid("timeout must be a positive integer"))?;
        if timeout == 0 || timeout > i32::MAX as u64 {
            return Err(invalid("timeout must be between 1 and 2147483647 seconds"));
        }
        let mode = value("obfs", "obfs", "obfs")?.ok_or_else(|| invalid("obfs mode is required (--obfs)"))?;
        let parameters = Parameters {
            mode: Mode::parse(&mode)?,
            host: value("obfs-host", "obfs-host", "obfs_host")?.unwrap_or_else(|| "cloudfront.net".to_owned()),
            port: remote_port,
            uri: value("obfs-uri", "obfs-uri", "obfs_uri")?.unwrap_or_else(|| "/".to_owned()),
            method: value("http-method", "http-method", "http_method")?.unwrap_or_else(|| "GET".to_owned()),
        };
        if parameters.host.len() > 255 || parameters.host.is_empty() || parameters.host.contains(['\r', '\n', '\0']) {
            return Err(invalid(
                "obfs-host must contain 1..255 bytes without line breaks or NUL",
            ));
        }
        if parameters.uri.is_empty()
            || parameters.uri.len() > 4096
            || parameters.uri.bytes().any(|b| b <= b' ' || b == 127)
        {
            return Err(invalid(
                "obfs-uri must be nonempty and contain no whitespace or control characters",
            ));
        }
        if parameters.method.is_empty()
            || parameters.method.len() > 64
            || !parameters
                .method
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
        {
            return Err(invalid("http-method must be an HTTP token"));
        }
        Ok(Self {
            remotes,
            local_host,
            local_port: parse_port(&local_port, "local_port")?,
            timeout: Duration::from_secs(timeout),
            parameters,
            ipv6_first: matches.get_flag("ipv6-first") || options.contains_key("6"),
            verbose: matches.get_flag("verbose") || options.contains_key("v"),
            fast_open: flag("fast-open", "fast-open", "fast_open")?,
            mptcp: flag("mptcp", "mptcp", "mptcp")?,
            interface: selected("interface", "i"),
            user: value("user", "a", "user")?,
            pid_file: matches.get_one::<String>("pid-file").map(PathBuf::from),
            nofile: value("nofile", "n", "nofile")?
                .map(|value| {
                    value
                        .parse::<u64>()
                        .map_err(|_| invalid("nofile must be a nonnegative integer"))
                })
                .transpose()?,
        })
    }
}

/// SIP003 escapes delimiters using backslashes. Split before unescaping, so
/// escaped '=' and ';' remain part of the value.
fn parse_plugin_options(input: &str) -> io::Result<HashMap<String, String>> {
    let mut options = HashMap::new();
    let mut key = String::new();
    let mut value = String::new();
    let mut in_value = false;
    let mut escaped = false;
    for c in input.chars().chain(std::iter::once(';')) {
        if escaped {
            if in_value {
                value.push(c)
            } else {
                key.push(c)
            }
            escaped = false;
        } else {
            match c {
                '\\' => escaped = true,
                '=' if !in_value => in_value = true,
                ';' => {
                    let current_value = std::mem::take(&mut value);
                    if !key.is_empty() {
                        options.insert(std::mem::take(&mut key), current_value);
                    }
                    in_value = false;
                }
                _ => {
                    if in_value {
                        value.push(c)
                    } else {
                        key.push(c)
                    }
                }
            }
        }
    }
    // A trailing backslash consumes the synthetic separator above.
    if !key.is_empty() || !value.is_empty() || escaped {
        return Err(invalid("invalid trailing escape in SS_PLUGIN_OPTIONS"));
    }
    Ok(options)
}

fn split_address(input: &str, fallback: u16) -> io::Result<(String, u16)> {
    if input.parse::<IpAddr>().is_ok() {
        return Ok((input.to_owned(), fallback));
    }
    if let Some(rest) = input.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| invalid("invalid bracketed server address"))?;
        let port = match tail.strip_prefix(':') {
            Some(port) => parse_port(port, "server port")?,
            None if tail.is_empty() => fallback,
            _ => return Err(invalid("invalid bracketed server address")),
        };
        return Ok((host.to_owned(), port));
    }
    match input.rsplit_once(':') {
        Some((host, port)) => Ok((host.to_owned(), parse_port(port, "server port")?)),
        None => Ok((input.to_owned(), fallback)),
    }
}

fn parse_port(value: &str, label: &str) -> io::Result<u16> {
    value
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| invalid(&format!("{label} must be between 1 and 65535")))
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
