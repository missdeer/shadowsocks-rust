//! Outbound proxy chain construction.

use std::io;

use log::trace;
use shadowsocks::{
    config::ServerConfig,
    context::SharedContext,
    relay::{socks5::Address, tcprelay::ProxyClientStream},
};

use crate::config::{ServerInstanceConfig, ServerProtocolConfig};
#[cfg(feature = "multi-protocol")]
use crate::config::{ServerTransportConfig, ServerTransportSecurity};

#[cfg(feature = "multi-protocol")]
use super::protocol::{establish_trojan, establish_vless};
use super::{
    OutboundProxyClient, OutboundProxyHop, OutboundProxyKind, TcpDialer, socks5::Socks5Negotiator,
    stream::OutboundProxyStream,
};
#[cfg(feature = "multi-protocol")]
use super::{anytls, hysteria, reality, vmess, websocket};

#[cfg(feature = "local-http")]
use super::http_connect::HttpConnectClient;

#[cfg(any(feature = "local-http-native-tls", feature = "local-http-rustls"))]
use super::tls::tls_connect;

impl OutboundProxyClient {
    /// Establish a TCP tunnel to `target` through the configured proxy
    /// chain. The first hop is dialled through `dialer`, allowing each
    /// caller to inject its own connect-options policy (`ConnectOpts`,
    /// bypass routing, ...).
    pub async fn connect_tcp<D>(
        &self,
        context: SharedContext,
        dialer: &D,
        target: &Address,
    ) -> io::Result<OutboundProxyStream>
    where
        D: TcpDialer + Sync,
    {
        connect_chain(self.hops(), &context, dialer, target).await
    }

    /// Establish an `sslocal` TCP tunnel whose configured main Shadowsocks
    /// server is the physical first hop and whose `outbound_proxy` entries
    /// are the subsequent hops.
    pub async fn connect_tcp_with_initial_server<D>(
        &self,
        context: SharedContext,
        dialer: &D,
        initial: &ServerInstanceConfig,
        target: &Address,
    ) -> io::Result<OutboundProxyStream>
    where
        D: TcpDialer + Sync,
    {
        connect_tcp_with_initial_server(self.hops(), &context, dialer, initial, target).await
    }

    /// Backwards-compatible entry point for callers that only have a
    /// Shadowsocks [`ServerConfig`].
    pub async fn connect_tcp_with_initial_shadowsocks<D>(
        &self,
        context: SharedContext,
        dialer: &D,
        initial: &ServerConfig,
        target: &Address,
    ) -> io::Result<OutboundProxyStream>
    where
        D: TcpDialer + Sync,
    {
        let initial = ServerInstanceConfig::with_server_config(initial.clone());
        self.connect_tcp_with_initial_server(context, dialer, &initial, target)
            .await
    }
}

/// Establish a primary-server tunnel followed by zero or more unchanged
/// `outbound_proxy` hops.
pub async fn connect_tcp_with_initial_server<D>(
    hops: &[OutboundProxyHop],
    context: &SharedContext,
    dialer: &D,
    initial: &ServerInstanceConfig,
    target: &Address,
) -> io::Result<OutboundProxyStream>
where
    D: TcpDialer + Sync,
{
    connect_chain_with_initial_server(hops, context, dialer, initial, target).await
}

pub(crate) async fn connect_chain<D>(
    hops: &[OutboundProxyHop],
    context: &SharedContext,
    dialer: &D,
    target: &Address,
) -> io::Result<OutboundProxyStream>
where
    D: TcpDialer + Sync,
{
    let Some(first_hop) = hops.first() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "empty outbound proxy chain",
        ));
    };

    first_hop.wait_plugin_started().await?;

    trace!("dialling first outbound proxy hop {}", first_hop.addr);
    let first_tcp = dialer.dial(&first_hop.addr).await?;
    let stream = OutboundProxyStream::from_tcp(first_tcp)?;

    negotiate_hops(hops, context, stream, target).await
}

async fn connect_chain_with_initial_server<D>(
    hops: &[OutboundProxyHop],
    context: &SharedContext,
    dialer: &D,
    initial: &ServerInstanceConfig,
    target: &Address,
) -> io::Result<OutboundProxyStream>
where
    D: TcpDialer + Sync,
{
    let next_target = hops.first().map(|hop| &hop.addr).unwrap_or(target);

    // Hysteria uses QUIC/UDP as its physical transport and therefore must
    // branch before the common TCP dial. The returned logical byte stream
    // still enters `negotiate_hops`, preserving the existing SOCKS5/SS
    // second-hop behavior unchanged.
    #[cfg(feature = "multi-protocol")]
    match &initial.protocol {
        ServerProtocolConfig::Hysteria {
            password,
            server_name,
            skip_certificate_verification,
            alpn,
            up_mbps,
            down_mbps,
            ..
        } => {
            let (local_addr, stream) = hysteria::establish(
                initial.config.addr(),
                server_name,
                *skip_certificate_verification,
                Some(alpn),
                password,
                *up_mbps,
                *down_mbps,
                None,
                next_target,
                hysteria::Version::One,
            )
            .await?;
            let stream = OutboundProxyStream::from_hysteria(local_addr, stream);
            return negotiate_hops(hops, context, stream, target).await;
        }
        ServerProtocolConfig::Hysteria2 {
            password,
            server_name,
            skip_certificate_verification,
            obfs,
            obfs_password,
            down_mbps,
            ..
        } => {
            let salamander_password = match obfs.as_deref() {
                None => None,
                Some(value) if value.eq_ignore_ascii_case("salamander") => obfs_password.as_deref(),
                Some(value) => {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        format!("unsupported Hysteria 2 obfuscation `{value}`"),
                    ));
                }
            };
            let (local_addr, stream) = hysteria::establish(
                initial.config.addr(),
                server_name,
                *skip_certificate_verification,
                None,
                password,
                None,
                *down_mbps,
                salamander_password,
                next_target,
                hysteria::Version::Two,
            )
            .await?;
            let stream = OutboundProxyStream::from_hysteria(local_addr, stream);
            return negotiate_hops(hops, context, stream, target).await;
        }
        _ => {}
    }

    let initial_addr: Address = initial.config.tcp_external_addr().into();
    trace!("dialling initial {:?} hop {}", initial.protocol, initial_addr);
    let initial_tcp = dialer.dial(&initial_addr).await?;
    let local_addr = initial_tcp.local_addr()?;
    let initial_stream = OutboundProxyStream::from_tcp_with_local_addr(initial_tcp, local_addr);
    let stream = match &initial.protocol {
        ServerProtocolConfig::Shadowsocks => {
            let stream =
                ProxyClientStream::from_stream(context.clone(), initial_stream, &initial.config, next_target.clone());
            OutboundProxyStream::from_ss(local_addr, stream)
        }
        #[cfg(feature = "multi-protocol")]
        ServerProtocolConfig::Vmess {
            uuid,
            cipher,
            transport,
            security,
            ..
        } => {
            let stream =
                establish_transport(initial_stream, transport, security, &initial.config.addr().to_string()).await?;
            let stream = vmess::establish(stream, cipher, uuid, next_target).await?;
            OutboundProxyStream::from_vmess(local_addr, stream)
        }
        #[cfg(feature = "multi-protocol")]
        ServerProtocolConfig::Vless {
            uuid,
            flow,
            transport,
            security,
            ..
        } => {
            if flow.as_deref() == Some("xtls-rprx-vision")
                && let ServerTransportSecurity::Reality {
                    server_name,
                    public_key,
                    short_id,
                    ..
                } = security
            {
                if !matches!(transport, ServerTransportConfig::Tcp) {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "VLESS Vision over REALITY requires TCP transport",
                    ));
                }
                let local_addr = initial_stream.local_addr()?;
                let stream =
                    reality::establish_vision(initial_stream, server_name, public_key, short_id, uuid, next_target)
                        .await?;
                OutboundProxyStream::from_vision(local_addr, stream)
            } else {
                let stream =
                    establish_transport(initial_stream, transport, security, &initial.config.addr().to_string())
                        .await?;
                if flow.as_deref().is_some_and(|flow| !flow.is_empty()) {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "VLESS flow is only supported for xtls-rprx-vision over REALITY",
                    ));
                }
                let stream = establish_vless(stream, uuid, flow.as_deref(), next_target).await?;
                OutboundProxyStream::from_vless(local_addr, stream)
            }
        }
        #[cfg(feature = "multi-protocol")]
        ServerProtocolConfig::Trojan {
            password,
            transport,
            security,
        } => {
            let stream =
                establish_transport(initial_stream, transport, security, &initial.config.addr().to_string()).await?;
            establish_trojan(stream, password, next_target).await?
        }
        #[cfg(feature = "multi-protocol")]
        ServerProtocolConfig::AnyTls {
            password,
            server_name,
            skip_certificate_verification,
            alpn,
            ..
        } => {
            let stream = tls_wrap_options(initial_stream, server_name, *skip_certificate_verification, alpn).await?;
            let stream = anytls::establish(stream, password, next_target).await?;
            OutboundProxyStream::from_anytls(local_addr, stream)
        }
        protocol => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("{} primary protocol runtime is not implemented yet", protocol.name()),
            ));
        }
    };

    negotiate_hops(hops, context, stream, target).await
}

#[cfg(feature = "multi-protocol")]
async fn establish_transport(
    mut stream: OutboundProxyStream,
    transport: &ServerTransportConfig,
    security: &ServerTransportSecurity,
    default_websocket_host: &str,
) -> io::Result<OutboundProxyStream> {
    stream = match security {
        ServerTransportSecurity::None => stream,
        ServerTransportSecurity::Tls {
            server_name,
            skip_certificate_verification,
            alpn,
        } => tls_wrap_options(stream, server_name, *skip_certificate_verification, alpn).await?,
        ServerTransportSecurity::Reality {
            server_name,
            public_key,
            short_id,
            ..
        } => {
            let local_addr = stream.local_addr()?;
            let stream = reality::establish(stream, server_name, public_key, short_id).await?;
            OutboundProxyStream::from_reality(local_addr, stream)
        }
    };

    match transport {
        ServerTransportConfig::Tcp => Ok(stream),
        ServerTransportConfig::WebSocket { path, host } => {
            let local_addr = stream.local_addr()?;
            let stream = websocket::connect(stream, path, host.as_deref().unwrap_or(default_websocket_host)).await?;
            Ok(OutboundProxyStream::from_websocket(local_addr, stream))
        }
    }
}

#[cfg(any(feature = "local-http-native-tls", feature = "local-http-rustls"))]
#[cfg(feature = "multi-protocol")]
async fn tls_wrap_options(
    stream: OutboundProxyStream,
    sni: &str,
    skip_certificate_verification: bool,
    alpn: &[String],
) -> io::Result<OutboundProxyStream> {
    let local_addr = stream.local_addr()?;
    let tls = super::tls::tls_connect_with_options(stream, sni, skip_certificate_verification, alpn).await?;
    Ok(OutboundProxyStream::from_tls(local_addr, tls))
}

#[cfg(not(any(feature = "local-http-native-tls", feature = "local-http-rustls")))]
#[cfg(feature = "multi-protocol")]
async fn tls_wrap_options(
    _stream: OutboundProxyStream,
    _sni: &str,
    _skip_certificate_verification: bool,
    _alpn: &[String],
) -> io::Result<OutboundProxyStream> {
    super::tls::tls_unsupported()
}

async fn negotiate_hops(
    hops: &[OutboundProxyHop],
    context: &SharedContext,
    mut stream: OutboundProxyStream,
    target: &Address,
) -> io::Result<OutboundProxyStream> {
    for (idx, hop) in hops.iter().enumerate() {
        // For HTTPS hops, wrap the wire layer with TLS *before* speaking
        // the application-level CONNECT verb.
        if hop.is_https() {
            stream = tls_wrap(stream, hop.tls_sni()).await?;
        }

        let next_target = hops.get(idx + 1).map(|h| &h.addr).unwrap_or(target);

        stream = negotiate_hop(context, stream, hop, next_target).await?;
    }

    Ok(stream)
}

/// Build a TCP control connection that *terminates at* `hops[hop_index]`
/// (i.e. previous hops are traversed via SOCKS5 TcpConnect, but the last
/// hop is left in its post-handshake "ready for an arbitrary command"
/// state — typically `UDP ASSOCIATE`).
///
/// All hops in `hops[..=hop_index]` must be SOCKS5; this helper is used
/// exclusively by the UDP outbound path which only supports
/// SOCKS5-only chains.
pub(crate) async fn connect_chain_for_udp_associate<D>(
    hops: &[OutboundProxyHop],
    hop_index: usize,
    context: &SharedContext,
    dialer: &D,
) -> io::Result<OutboundProxyStream>
where
    D: TcpDialer + Sync,
{
    debug_assert!(hop_index < hops.len());
    let prefix = &hops[..hop_index];
    let target_hop = &hops[hop_index];

    if hop_index == 0 {
        // Direct dial.
        let tcp = dialer.dial(&target_hop.addr).await?;
        return OutboundProxyStream::from_tcp(tcp);
    }

    // Reuse `connect_chain`: target = hops[hop_index].addr; the chain
    // builder will SOCKS5-TcpConnect through prefix and leave the byte
    // stream pointed at `hops[hop_index]` ready for the caller to issue
    // its own SOCKS5 handshake / UdpAssociate command on top.
    connect_chain(prefix, context, dialer, &target_hop.addr).await
}

async fn negotiate_hop(
    context: &SharedContext,
    mut stream: OutboundProxyStream,
    hop: &OutboundProxyHop,
    next_target: &Address,
) -> io::Result<OutboundProxyStream> {
    match &hop.kind {
        OutboundProxyKind::Socks5 { auth } => {
            Socks5Negotiator::establish_tcp(&mut stream, next_target.clone(), auth)
                .await
                .map_err(io::Error::other)?;
            Ok(stream)
        }
        #[cfg(feature = "local-http")]
        OutboundProxyKind::Http { auth } | OutboundProxyKind::Https { auth, .. } => {
            let local_addr = stream.local_addr()?;
            let tunnel = HttpConnectClient::establish(stream, next_target, auth).await?;
            Ok(OutboundProxyStream::from_http(local_addr, tunnel))
        }
        #[cfg(not(feature = "local-http"))]
        OutboundProxyKind::Http { .. } | OutboundProxyKind::Https { .. } => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "HTTP/HTTPS outbound proxy requires the `local-http` feature",
        )),
        OutboundProxyKind::Ss { svr_cfg, .. } => {
            let local_addr = stream.local_addr()?;
            let stream = ProxyClientStream::from_stream(context.clone(), stream, svr_cfg, next_target.clone());
            Ok(OutboundProxyStream::from_ss(local_addr, stream))
        }
    }
}

#[cfg(any(feature = "local-http-native-tls", feature = "local-http-rustls"))]
async fn tls_wrap(stream: OutboundProxyStream, sni: &str) -> io::Result<OutboundProxyStream> {
    let local_addr = stream.local_addr()?;
    let tls = tls_connect(stream, sni).await?;
    Ok(OutboundProxyStream::from_tls(local_addr, tls))
}

#[cfg(not(any(feature = "local-http-native-tls", feature = "local-http-rustls")))]
async fn tls_wrap(_stream: OutboundProxyStream, _sni: &str) -> io::Result<OutboundProxyStream> {
    super::tls::tls_unsupported()
}
