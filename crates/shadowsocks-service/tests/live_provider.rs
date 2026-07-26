//! Explicitly ignored interoperability tests for local, credential-bearing
//! provider files. The test never prints node configuration or credentials.

#![cfg(feature = "multi-protocol")]

use std::{
    fs, io,
    net::{IpAddr, SocketAddr},
    path::Path,
    process::Command,
    time::Duration,
};

use serde::Deserialize;
use shadowsocks_service::{
    config::{
        Config, ConfigType, OutboundProxy, ServerInstanceConfig, ServerProtocolConfig, ServerTransportConfig,
        ServerTransportSecurity,
    },
    net::{OutboundProxyClient, TcpDialer, connect_tcp_with_initial_server},
    shadowsocks::{
        config::{ServerAddr, ServerConfig, ServerType},
        context::{Context, SharedContext},
        crypto::CipherKind,
        net::{ConnectOpts, TcpStream},
        plugin::{Plugin, PluginConfig, PluginMode},
        relay::socks5::Address,
    },
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const NORMALIZE_VM_NODE: &str = r#"
import json, sys, yaml
try:
    with open(sys.argv[1], 'r', encoding='utf-8') as stream:
        document = yaml.safe_load(stream)
    nodes = []
    for proxy in document.get('proxies', []):
        if str(proxy.get('type', '')).lower() != 'vmess':
            continue
        ws = proxy.get('ws-opts') or {}
        headers = ws.get('headers') or {}
        host = headers.get('Host') or headers.get('host')
        nodes.append({
            'server': proxy.get('server'),
            'port': proxy.get('port'),
            'uuid': proxy.get('uuid'),
            'cipher': proxy.get('cipher') or 'auto',
            'alter_id': proxy.get('alterId') or 0,
            'network': proxy.get('network') or 'tcp',
            'ws_path': ws.get('path') or '/',
            'ws_host': host,
            'tls': bool(proxy.get('tls', False)),
            'server_name': proxy.get('servername') or proxy.get('sni'),
            'skip_certificate_verification': bool(proxy.get('skip-cert-verify', False)),
        })
    print(json.dumps(nodes))
except Exception as error:
    print(type(error).__name__, file=sys.stderr)
    sys.exit(1)
"#;

const NORMALIZE_SS_NODE: &str = r#"
import json, sys, yaml
try:
    with open(sys.argv[1], 'r', encoding='utf-8') as stream:
        document = yaml.safe_load(stream)
    nodes = []
    for proxy in document.get('proxies', []):
        if str(proxy.get('type', '')).lower() != 'ss':
            continue
        plugin = proxy.get('plugin-opts') or {}
        nodes.append({
            'server': proxy.get('server'),
            'port': proxy.get('port'),
            'password': proxy.get('password'),
            'method': proxy.get('cipher'),
            'plugin_mode': plugin.get('mode'),
            'plugin_host': plugin.get('host'),
        })
    print(json.dumps(nodes))
except Exception as error:
    print(type(error).__name__, file=sys.stderr)
    sys.exit(1)
"#;

#[derive(Deserialize)]
struct VmessNode {
    server: String,
    port: u16,
    uuid: String,
    cipher: String,
    alter_id: u16,
    network: String,
    ws_path: String,
    ws_host: Option<String>,
    tls: bool,
    server_name: Option<String>,
    skip_certificate_verification: bool,
}

#[derive(Deserialize)]
struct ShadowsocksNode {
    server: String,
    port: u16,
    password: String,
    method: String,
    plugin_mode: Option<String>,
    plugin_host: Option<String>,
}

struct DirectDialer {
    context: SharedContext,
}

impl TcpDialer for DirectDialer {
    async fn dial(&self, addr: &Address) -> io::Result<TcpStream> {
        TcpStream::connect_remote_with_opts(&self.context, addr, &ConnectOpts::default()).await
    }
}

fn load_vmess_nodes() -> Vec<VmessNode> {
    let provider_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../mojie.yaml");
    let output = Command::new("python")
        .args(["-c", NORMALIZE_VM_NODE])
        .arg(provider_path)
        .output()
        .expect("Python with PyYAML is required for the explicit live test");
    assert!(
        output.status.success(),
        "provider config normalization failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("normalized provider nodes are invalid")
}

fn load_shadowsocks_nodes() -> Vec<ShadowsocksNode> {
    let provider_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Flower_SS.yaml");
    let output = Command::new("python")
        .args(["-c", NORMALIZE_SS_NODE])
        .arg(provider_path)
        .output()
        .expect("Python with PyYAML is required for the explicit live test");
    assert!(
        output.status.success(),
        "provider config normalization failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("normalized provider nodes are invalid")
}

fn primary(node: &VmessNode) -> ServerInstanceConfig {
    let address = match node.server.parse::<IpAddr>() {
        Ok(ip) => ServerAddr::SocketAddr(SocketAddr::new(ip, node.port)),
        Err(_) => ServerAddr::DomainName(node.server.clone(), node.port),
    };
    let metadata = ServerConfig::new(address, "", CipherKind::NONE).expect("metadata config");
    let transport = match node.network.as_str() {
        "tcp" => ServerTransportConfig::Tcp,
        "ws" | "websocket" => ServerTransportConfig::WebSocket {
            path: node.ws_path.clone(),
            host: node.ws_host.clone(),
        },
        _ => panic!("provider VMess node uses an unsupported transport"),
    };
    let security = if node.tls {
        ServerTransportSecurity::Tls {
            server_name: node.server_name.clone().unwrap_or_else(|| node.server.clone()),
            skip_certificate_verification: node.skip_certificate_verification,
            alpn: Vec::new(),
        }
    } else {
        ServerTransportSecurity::None
    };
    let mut primary = ServerInstanceConfig::with_server_config(metadata);
    primary.protocol = ServerProtocolConfig::Vmess {
        uuid: node.uuid.clone(),
        cipher: node.cipher.clone(),
        alter_id: node.alter_id,
        transport,
        security,
    };
    primary
}

#[test]
#[ignore = "validates local credential-bearing files under conf/"]
fn generated_provider_configs_parse() {
    validate_generated_configs("conf", false);
}

#[test]
#[ignore = "validates local credential-bearing files under conf-chain/"]
fn generated_chain_configs_parse() {
    validate_generated_configs("conf-chain", true);
}

fn validate_generated_configs(directory: &str, expect_second_hop: bool) {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let conf_root = workspace_root.join(directory);
    let usbwh = Config::load_from_file(workspace_root.join("usbwh.conf"), ConfigType::Local).expect("usbwh config");
    let expected_second_hop = &usbwh.server[0].config;
    let mut count = 0usize;

    for protocol_dir in fs::read_dir(conf_root).expect("read conf directory") {
        let protocol_dir = protocol_dir.expect("read protocol directory").path();
        if !protocol_dir.is_dir() {
            continue;
        }
        for entry in fs::read_dir(protocol_dir).expect("read protocol configs") {
            let path = entry.expect("read generated config").path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }

            let config = Config::load_from_file(path, ConfigType::Local).expect("parse generated provider config");
            config.check_integrity().expect("validate generated provider config");
            assert_eq!(config.server.len(), 1);
            assert_eq!(config.local.len(), 1);
            assert_eq!(
                config.local[0].config.addr.as_ref().expect("local address").port(),
                65432
            );
            if expect_second_hop {
                assert_eq!(config.outbound_proxy.len(), 1);
                let OutboundProxy::Ss(hop) = &config.outbound_proxy[0] else {
                    panic!("generated second hop is not Shadowsocks");
                };
                assert_eq!(hop.svr_cfg.addr(), expected_second_hop.addr());
                assert_eq!(hop.svr_cfg.method(), expected_second_hop.method());
                assert_eq!(hop.svr_cfg.password(), expected_second_hop.password());
            } else {
                assert!(config.outbound_proxy.is_empty());
            }
            count += 1;
        }
    }

    assert_eq!(count, 225);
}

#[tokio::test]
#[ignore = "uses real provider nodes from mojie.yaml"]
async fn vmess_provider_first_hop() {
    assert!(
        try_nodes(None).await,
        "no VMess provider node passed the first-hop test"
    );
}

#[tokio::test]
#[ignore = "uses real provider nodes from mojie.yaml and usbwh.conf"]
async fn vmess_provider_then_usbwh_shadowsocks() {
    let usbwh_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../usbwh.conf");
    let config = Config::load_from_file(usbwh_path, ConfigType::Local).expect("usbwh config");
    let second_hop = OutboundProxy::from_url(&config.server[0].config.to_url()).expect("SS second hop");
    assert!(
        try_nodes(Some(second_hop)).await,
        "no VMess provider node passed the VMess-to-SS chain test"
    );
}

#[tokio::test]
#[ignore = "uses real AnyTLS provider nodes under conf/anytls"]
async fn anytls_provider_first_hop() {
    assert!(
        try_generated_protocol("anytls", false).await,
        "no AnyTLS provider node passed the first-hop test"
    );
}

#[tokio::test]
#[ignore = "uses real AnyTLS provider nodes and usbwh.conf"]
async fn anytls_provider_then_usbwh_shadowsocks() {
    assert!(
        try_generated_protocol("anytls", true).await,
        "no AnyTLS provider node passed the AnyTLS-to-SS chain test"
    );
}

#[tokio::test]
#[ignore = "uses real Hysteria 2 provider nodes under conf/hysteria2"]
async fn hysteria2_provider_first_hop() {
    assert!(
        try_generated_protocol("hysteria2", false).await,
        "no Hysteria 2 provider node passed the first-hop test"
    );
}

#[tokio::test]
#[ignore = "uses real Hysteria 2 provider nodes and usbwh.conf"]
async fn hysteria2_provider_then_usbwh_shadowsocks() {
    assert!(
        try_generated_protocol("hysteria2", true).await,
        "no Hysteria 2 provider node passed the Hysteria-2-to-SS chain test"
    );
}

#[tokio::test]
#[ignore = "uses a real VLESS REALITY/Vision provider node under conf/vless"]
async fn vless_reality_vision_provider_first_hop() {
    assert!(
        try_generated_protocol("vless", false).await,
        "no VLESS REALITY/Vision provider node passed the first-hop test"
    );
}

#[tokio::test]
#[ignore = "uses a real VLESS REALITY/Vision provider node and usbwh.conf"]
async fn vless_reality_vision_provider_then_usbwh_shadowsocks() {
    assert!(
        try_generated_protocol("vless", true).await,
        "no VLESS REALITY/Vision node passed the VLESS-to-SS chain test"
    );
}

#[tokio::test]
#[ignore = "uses real provider nodes from Flower_SS.yaml and a local SIP003 executable"]
async fn shadowsocks_obfs_provider_first_hop() {
    assert!(
        try_shadowsocks_nodes(None).await,
        "no SS+obfs provider node passed the first-hop test"
    );
}

#[tokio::test]
#[ignore = "uses real provider nodes from Flower_SS.yaml and usbwh.conf"]
async fn shadowsocks_obfs_provider_then_usbwh_shadowsocks() {
    let usbwh_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../usbwh.conf");
    let config = Config::load_from_file(usbwh_path, ConfigType::Local).expect("usbwh config");
    let second_hop = OutboundProxy::from_url(&config.server[0].config.to_url()).expect("SS second hop");
    assert!(
        try_shadowsocks_nodes(Some(second_hop)).await,
        "no SS+obfs provider node passed the SS-to-SS chain test"
    );
}

async fn try_nodes(second_hop: Option<OutboundProxy>) -> bool {
    let nodes = load_vmess_nodes();
    assert!(!nodes.is_empty(), "provider file contains no VMess nodes");
    for node in &nodes {
        let attempt = tokio::time::timeout(Duration::from_secs(12), try_node(node, second_hop.as_ref())).await;
        if matches!(attempt, Ok(Ok(()))) {
            return true;
        }
    }
    false
}

async fn try_generated_protocol(protocol: &str, chained: bool) -> bool {
    let directory = if chained { "conf-chain" } else { "conf" };
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(directory)
        .join(protocol);
    let entries = fs::read_dir(root).expect("read generated provider directory");
    let mut attempted = 0usize;
    for entry in entries {
        let path = entry.expect("read generated provider config").path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        attempted += 1;
        let attempt = tokio::time::timeout(Duration::from_secs(12), try_generated_config(&path)).await;
        if matches!(attempt, Ok(Ok(()))) {
            return true;
        }
    }
    assert_ne!(attempted, 0, "generated provider directory is empty");
    false
}

async fn try_generated_config(path: &Path) -> io::Result<()> {
    let config = Config::load_from_file(path, ConfigType::Local)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let context = Context::new_shared(ServerType::Local);
    let dialer = DirectDialer {
        context: context.clone(),
    };
    let target = Address::DomainNameAddress("example.com".to_owned(), 80);
    let mut stream = if config.outbound_proxy.is_empty() {
        connect_tcp_with_initial_server(&[], &context, &dialer, &config.server[0], &target).await?
    } else {
        let client = OutboundProxyClient::try_from_config_after_main_server(&config.outbound_proxy)?;
        client
            .connect_tcp_with_initial_server(context, &dialer, &config.server[0], &target)
            .await?
    };
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
        .await?;
    stream.flush().await?;
    let mut prefix = [0u8; 5];
    stream.read_exact(&mut prefix).await?;
    if &prefix != b"HTTP/" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected live test response",
        ));
    }
    Ok(())
}

async fn try_node(node: &VmessNode, second_hop: Option<&OutboundProxy>) -> io::Result<()> {
    let context = Context::new_shared(ServerType::Local);
    let dialer = DirectDialer {
        context: context.clone(),
    };
    let primary = primary(node);
    let target = Address::DomainNameAddress("example.com".to_owned(), 80);
    let mut stream = match second_hop {
        Some(second_hop) => {
            let client = OutboundProxyClient::try_from_config_after_main_server(std::slice::from_ref(second_hop))?;
            client
                .connect_tcp_with_initial_server(context, &dialer, &primary, &target)
                .await?
        }
        None => connect_tcp_with_initial_server(&[], &context, &dialer, &primary, &target).await?,
    };
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
        .await?;
    stream.flush().await?;
    let mut prefix = [0u8; 5];
    stream.read_exact(&mut prefix).await?;
    if &prefix != b"HTTP/" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected live test response",
        ));
    }
    Ok(())
}

async fn try_shadowsocks_nodes(second_hop: Option<OutboundProxy>) -> bool {
    let nodes = load_shadowsocks_nodes();
    assert!(!nodes.is_empty(), "provider file contains no Shadowsocks nodes");
    // Keep this explicit live test bounded even if a provider file contains
    // many stale entries. Eight nodes is enough to sample different regions
    // without turning a local check into a multi-minute sweep.
    for node in nodes.iter().take(8) {
        let attempt =
            tokio::time::timeout(Duration::from_secs(6), try_shadowsocks_node(node, second_hop.as_ref())).await;
        if matches!(attempt, Ok(Ok(()))) {
            return true;
        }
    }
    false
}

async fn try_shadowsocks_node(node: &ShadowsocksNode, second_hop: Option<&OutboundProxy>) -> io::Result<()> {
    let address = match node.server.parse::<IpAddr>() {
        Ok(ip) => ServerAddr::SocketAddr(SocketAddr::new(ip, node.port)),
        Err(_) => ServerAddr::DomainName(node.server.clone(), node.port),
    };
    let method = node
        .method
        .parse::<CipherKind>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "unsupported provider SS cipher"))?;
    let mut server = ServerConfig::new(address, &node.password, method)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid provider SS config"))?;
    let executable = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../obfs-local.exe");
    let plugin_options = match (&node.plugin_mode, &node.plugin_host) {
        (Some(mode), Some(host)) => Some(format!("obfs={mode};obfs-host={host}")),
        (Some(mode), None) => Some(format!("obfs={mode}")),
        _ => None,
    };
    let plugin_config = PluginConfig {
        plugin: executable.to_string_lossy().into_owned(),
        plugin_opts: plugin_options,
        plugin_args: Vec::new(),
        plugin_mode: shadowsocks_service::shadowsocks::config::Mode::TcpOnly,
    };
    let plugin = Plugin::start(&plugin_config, server.addr(), PluginMode::Client)?;
    server.set_plugin(plugin_config);
    server.set_plugin_addr(plugin.local_addr().into());
    if !plugin.wait_started(Duration::from_secs(3)).await {
        return Err(io::Error::new(io::ErrorKind::TimedOut, "SIP003 plugin did not start"));
    }

    let primary = ServerInstanceConfig::with_server_config(server);
    let context = Context::new_shared(ServerType::Local);
    let dialer = DirectDialer {
        context: context.clone(),
    };
    let target = Address::DomainNameAddress("example.com".to_owned(), 80);
    let mut stream = match second_hop {
        Some(second_hop) => {
            let client = OutboundProxyClient::try_from_config_after_main_server(std::slice::from_ref(second_hop))?;
            client
                .connect_tcp_with_initial_server(context, &dialer, &primary, &target)
                .await?
        }
        None => connect_tcp_with_initial_server(&[], &context, &dialer, &primary, &target).await?,
    };
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
        .await?;
    stream.flush().await?;
    let mut prefix = [0u8; 5];
    stream.read_exact(&mut prefix).await?;
    if &prefix != b"HTTP/" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected live test response",
        ));
    }
    drop(plugin);
    Ok(())
}
