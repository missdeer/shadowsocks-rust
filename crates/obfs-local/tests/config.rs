// SPDX-License-Identifier: GPL-3.0-or-later

use std::{collections::HashMap, fs, path::PathBuf};

use obfs_local::{
    config::{self, Config},
    protocol::Mode,
};

fn environment() -> HashMap<String, String> {
    [
        ("SS_REMOTE_HOST", "127.0.0.1"),
        ("SS_REMOTE_PORT", "443"),
        ("SS_LOCAL_HOST", "127.0.0.1"),
        ("SS_LOCAL_PORT", "12345"),
        ("SS_PLUGIN_OPTIONS", "obfs=http;obfs-host=example.com"),
    ]
    .into_iter()
    .map(|(key, value)| (key.into(), value.into()))
    .collect()
}

fn parse(args: &[&str], env: &HashMap<String, String>) -> std::io::Result<Config> {
    Config::from_matches(&config::command().try_get_matches_from(args).unwrap(), env)
}

#[test]
fn sip003_defaults_and_command_line_overrides() {
    let env = environment();
    let config = parse(&["obfs-local"], &env).unwrap();
    assert_eq!(config.parameters.mode, Mode::Http);
    assert_eq!(config.timeout.as_secs(), 600);
    let config = parse(&["obfs-local", "-p", "8443", "-l", "54321", "--obfs=tls", "-v6"], &env).unwrap();
    assert_eq!(config.parameters.mode, Mode::Tls);
    assert_eq!(config.parameters.port, 8443);
    assert_eq!(config.remotes[0].port, 8443);
    assert_eq!(config.local_port, 54321);
    assert!(config.verbose && config.ipv6_first);
}

#[test]
fn escaped_plugin_values_and_multiple_remote_hosts() {
    let mut env = environment();
    env.insert("SS_REMOTE_HOST".into(), "localhost|127.0.0.1".into());
    env.insert(
        "SS_PLUGIN_OPTIONS".into(),
        r"obfs=http;obfs-uri=/foo\;bar\=baz;t=17;v;unknown=value".into(),
    );
    let config = parse(&["obfs-local", "-s", "::1"], &env).unwrap();
    assert_eq!(config.remotes.len(), 3);
    assert_eq!(config.parameters.uri, "/foo;bar=baz");
    assert_eq!(config.timeout.as_secs(), 17);
    assert!(config.verbose);
    env.insert("SS_PLUGIN_OPTIONS".into(), "obfs=http;obfs-uri=/bad\\".into());
    assert!(parse(&["obfs-local"], &env).is_err());
}

struct TemporaryConfig(PathBuf);
impl TemporaryConfig {
    fn new(data: &str) -> Self {
        let path = std::env::temp_dir().join(format!("obfs-config-{:x}.json", rand::random::<u64>()));
        fs::write(&path, data).unwrap();
        Self(path)
    }
}
impl Drop for TemporaryConfig {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

#[test]
fn json_config_accepts_integer_or_string_ports_and_cli_takes_precedence() {
    let file = TemporaryConfig::new(
        r#"{
        "server":["example.com:1234","[::1]:5678","127.0.0.1"],
        "server_port":"443", "local_port":12345, "obfs":"tls",
        "obfs_host":"example.net", "timeout":23, "fast_open":true
    }"#,
    );
    let config = parse(
        &["obfs-local", "-c", file.0.to_str().unwrap(), "-t", "31"],
        &HashMap::new(),
    )
    .unwrap();
    assert_eq!(
        config.remotes.iter().map(|r| r.port).collect::<Vec<_>>(),
        [1234, 5678, 443]
    );
    assert_eq!(config.remotes[1].host, "::1");
    assert_eq!(config.timeout.as_secs(), 31);
    assert!(config.fast_open);
    let config = parse(&["obfs-local", "-c", file.0.to_str().unwrap()], &environment()).unwrap();
    assert_eq!(config.remotes.len(), 1);
    assert_eq!(config.parameters.mode, Mode::Http);
    assert_eq!(config.parameters.host, "example.com");
}

#[test]
fn original_client_options_are_accepted_and_bad_configuration_is_rejected() {
    parse(
        &[
            "obfs-local",
            "-i",
            "ethernet",
            "-a",
            "nobody",
            "-f",
            "pid",
            "-n",
            "4096",
            "--fast-open",
            "--mptcp",
            "--http-method",
            "POST",
            "--obfs-uri",
            "/path",
        ],
        &environment(),
    )
    .unwrap();
    for extra in [
        ["-t", "0"],
        ["-p", "65536"],
        ["--obfs", "quic"],
        ["--obfs-host", "bad\r\nhost"],
    ] {
        assert!(parse(&["obfs-local", extra[0], extra[1]], &environment()).is_err());
    }
    assert!(parse(&["obfs-local"], &HashMap::new()).is_err());
    assert!(
        config::command()
            .try_get_matches_from(["obfs-local", "--unknown"])
            .is_err()
    );
}
