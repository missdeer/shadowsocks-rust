#![cfg(all(feature = "aead-cipher", feature = "multi-protocol"))]

use std::{io, net::SocketAddr};

use shadowsocks_service::{
    config::{
        OutboundProxy, ServerInstanceConfig, ServerProtocolConfig, ServerTransportConfig, ServerTransportSecurity,
    },
    net::{OutboundProxyClient, TcpDialer, connect_tcp_with_initial_server},
    shadowsocks::{
        ProxyListener,
        config::{ServerConfig, ServerType},
        context::{Context, SharedContext},
        crypto::CipherKind,
        net::{ConnectOpts, TcpStream as ShadowTcpStream},
        relay::socks5::Address,
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
};

struct DirectDialer {
    context: SharedContext,
}

impl TcpDialer for DirectDialer {
    async fn dial(&self, addr: &Address) -> io::Result<ShadowTcpStream> {
        ShadowTcpStream::connect_remote_with_opts(&self.context, addr, &ConnectOpts::default()).await
    }
}

async fn spawn_echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut read, mut write) = stream.split();
                tokio::io::copy(&mut read, &mut write).await.unwrap();
            });
        }
    });
    addr
}

async fn make_ss_listener(password: &str) -> (ProxyListener, ServerConfig) {
    let bind_config = ServerConfig::new(
        "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
        password,
        CipherKind::AES_128_GCM,
    )
    .unwrap();
    let listener = ProxyListener::bind(Context::new_shared(ServerType::Server), &bind_config)
        .await
        .unwrap();
    let client_config = ServerConfig::new(listener.local_addr().unwrap(), password, CipherKind::AES_128_GCM).unwrap();
    (listener, client_config)
}

fn spawn_ss_relay(listener: ProxyListener, targets: mpsc::UnboundedSender<Address>) {
    tokio::spawn(async move {
        while let Ok((mut inbound, _)) = listener.accept().await {
            let targets = targets.clone();
            tokio::spawn(async move {
                let target = inbound.handshake().await.unwrap();
                targets.send(target.clone()).unwrap();
                let mut outbound = connect_target(&target).await;
                tokio::io::copy_bidirectional(&mut inbound, &mut outbound)
                    .await
                    .unwrap();
            });
        }
    });
}

async fn spawn_vless_relay(targets: mpsc::UnboundedSender<Address>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut inbound, _)) = listener.accept().await {
            let targets = targets.clone();
            tokio::spawn(async move {
                let mut fixed = [0u8; 18];
                inbound.read_exact(&mut fixed).await.unwrap();
                assert_eq!(fixed[0], 0);
                let addons_len = fixed[17] as usize;
                let mut addons = vec![0u8; addons_len];
                inbound.read_exact(&mut addons).await.unwrap();
                assert_eq!(inbound.read_u8().await.unwrap(), 1);
                let target = read_vless_address(&mut inbound).await;
                targets.send(target.clone()).unwrap();

                let mut outbound = connect_target(&target).await;
                inbound.write_all(&[0, 0]).await.unwrap();
                tokio::io::copy_bidirectional(&mut inbound, &mut outbound)
                    .await
                    .unwrap();
            });
        }
    });
    addr
}

async fn spawn_trojan_relay(targets: mpsc::UnboundedSender<Address>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut inbound, _)) = listener.accept().await {
            let targets = targets.clone();
            tokio::spawn(async move {
                let mut hash = [0u8; 56];
                inbound.read_exact(&mut hash).await.unwrap();
                assert!(hash.iter().all(u8::is_ascii_hexdigit));
                let mut crlf = [0u8; 2];
                inbound.read_exact(&mut crlf).await.unwrap();
                assert_eq!(&crlf, b"\r\n");
                assert_eq!(inbound.read_u8().await.unwrap(), 1);
                let target = read_socks_address(&mut inbound).await;
                inbound.read_exact(&mut crlf).await.unwrap();
                assert_eq!(&crlf, b"\r\n");
                targets.send(target.clone()).unwrap();

                let mut outbound = connect_target(&target).await;
                tokio::io::copy_bidirectional(&mut inbound, &mut outbound)
                    .await
                    .unwrap();
            });
        }
    });
    addr
}

fn primary_instance(addr: SocketAddr, protocol: ServerProtocolConfig) -> ServerInstanceConfig {
    let metadata = ServerConfig::new(addr, "", CipherKind::NONE).unwrap();
    let mut instance = ServerInstanceConfig::with_server_config(metadata);
    instance.protocol = protocol;
    instance
}

#[tokio::test]
async fn vless_primary_server_precedes_shadowsocks_outbound_hop() {
    let echo_addr = spawn_echo_server().await;
    let (ss_listener, ss_config) = make_ss_listener("second-hop-password").await;
    let ss_addr = ss_listener.local_addr().unwrap();
    let (ss_targets_tx, mut ss_targets_rx) = mpsc::unbounded_channel();
    spawn_ss_relay(ss_listener, ss_targets_tx);

    let (vless_targets_tx, mut vless_targets_rx) = mpsc::unbounded_channel();
    let vless_addr = spawn_vless_relay(vless_targets_tx).await;
    let primary = primary_instance(
        vless_addr,
        ServerProtocolConfig::Vless {
            uuid: "550e8400-e29b-41d4-a716-446655440000".to_owned(),
            flow: None,
            packet_encoding: None,
            transport: ServerTransportConfig::Tcp,
            security: ServerTransportSecurity::None,
        },
    );

    let ss_proxy = OutboundProxy::from_url(&ss_config.to_url()).unwrap();
    let client = OutboundProxyClient::try_from_config_after_main_server(&[ss_proxy]).unwrap();
    let context = Context::new_shared(ServerType::Local);
    let dialer = DirectDialer {
        context: context.clone(),
    };
    let mut stream = client
        .connect_tcp_with_initial_server(context, &dialer, &primary, &Address::from(echo_addr))
        .await
        .unwrap();

    stream.write_all(b"vless then shadowsocks").await.unwrap();
    assert_eq!(vless_targets_rx.recv().await, Some(Address::from(ss_addr)));
    assert_eq!(ss_targets_rx.recv().await, Some(Address::from(echo_addr)));
    let mut echoed = [0u8; 22];
    stream.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"vless then shadowsocks");
}

#[tokio::test]
async fn trojan_primary_server_connects_without_outbound_hops() {
    let echo_addr = spawn_echo_server().await;
    let (targets_tx, mut targets_rx) = mpsc::unbounded_channel();
    let trojan_addr = spawn_trojan_relay(targets_tx).await;
    let primary = primary_instance(
        trojan_addr,
        ServerProtocolConfig::Trojan {
            password: "test-password".to_owned(),
            transport: ServerTransportConfig::Tcp,
            security: ServerTransportSecurity::None,
        },
    );
    let context = Context::new_shared(ServerType::Local);
    let dialer = DirectDialer {
        context: context.clone(),
    };
    let mut stream = connect_tcp_with_initial_server(&[], &context, &dialer, &primary, &Address::from(echo_addr))
        .await
        .unwrap();

    stream.write_all(b"trojan direct").await.unwrap();
    assert_eq!(targets_rx.recv().await, Some(Address::from(echo_addr)));
    let mut echoed = [0u8; 13];
    stream.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"trojan direct");
}

async fn connect_target(target: &Address) -> TcpStream {
    match target {
        Address::SocketAddress(addr) => TcpStream::connect(addr).await.unwrap(),
        Address::DomainNameAddress(host, port) => TcpStream::connect((host.as_str(), *port)).await.unwrap(),
    }
}

async fn read_vless_address(stream: &mut TcpStream) -> Address {
    let port = stream.read_u16().await.unwrap();
    match stream.read_u8().await.unwrap() {
        1 => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets).await.unwrap();
            Address::SocketAddress(SocketAddr::from((octets, port)))
        }
        2 => {
            let len = stream.read_u8().await.unwrap() as usize;
            let mut domain = vec![0u8; len];
            stream.read_exact(&mut domain).await.unwrap();
            Address::DomainNameAddress(String::from_utf8(domain).unwrap(), port)
        }
        3 => {
            let mut octets = [0u8; 16];
            stream.read_exact(&mut octets).await.unwrap();
            Address::SocketAddress(SocketAddr::from((octets, port)))
        }
        atyp => panic!("unexpected VLESS address type {atyp}"),
    }
}

async fn read_socks_address(stream: &mut TcpStream) -> Address {
    match stream.read_u8().await.unwrap() {
        1 => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets).await.unwrap();
            let port = stream.read_u16().await.unwrap();
            Address::SocketAddress(SocketAddr::from((octets, port)))
        }
        3 => {
            let len = stream.read_u8().await.unwrap() as usize;
            let mut domain = vec![0u8; len];
            stream.read_exact(&mut domain).await.unwrap();
            let port = stream.read_u16().await.unwrap();
            Address::DomainNameAddress(String::from_utf8(domain).unwrap(), port)
        }
        4 => {
            let mut octets = [0u8; 16];
            stream.read_exact(&mut octets).await.unwrap();
            let port = stream.read_u16().await.unwrap();
            Address::SocketAddress(SocketAddr::from((octets, port)))
        }
        atyp => panic!("unexpected SOCKS address type {atyp}"),
    }
}
