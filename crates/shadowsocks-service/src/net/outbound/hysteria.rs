//! Client-side Hysteria 1 and Hysteria 2 TCP tunnels.
//!
//! Both protocols carry proxied TCP connections in native QUIC bidirectional
//! streams, but their control planes are intentionally kept separate:
//! Hysteria 1 uses its version-3 binary control stream, while Hysteria 2 uses
//! HTTP/3 authentication and prefixes data streams with frame type `0x401`.

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use http::Request;
use pin_project::pin_project;
use quinn::{Endpoint, RecvStream, SendStream, crypto::rustls::QuicClientConfig};
use rand::{Rng, RngExt};
use shadowsocks::{config::ServerAddr, relay::socks5::Address};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::{salamander, tls::rustls_client_config_with_options};

const AUTH_OK_STATUS: u16 = 233;
const HYSTERIA2_TCP_REQUEST: u64 = 0x401;
const HYSTERIA1_PROTOCOL_VERSION: u8 = 3;
const MAX_RESPONSE_FIELD: u64 = 4096;
const PADDING_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Version {
    One,
    Two,
}

/// A TCP-like stream backed by one QUIC bidirectional stream. The endpoint
/// and connection handles deliberately live alongside the streams so that
/// dropping the returned value tears down all associated QUIC state.
#[pin_project]
pub struct HysteriaStream {
    #[pin]
    send: SendStream,
    #[pin]
    recv: RecvStream,
    _control: Option<(SendStream, RecvStream)>,
    _connection: quinn::Connection,
    _endpoint: Endpoint,
}

impl AsyncRead for HysteriaStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        self.project().recv.poll_read(cx, buf)
    }
}

impl AsyncWrite for HysteriaStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.project()
            .send
            .poll_write(cx, buf)
            .map(|result| result.map_err(io::Error::other))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().send.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().send.poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.send.is_write_vectored()
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.project().send.poll_write_vectored(cx, bufs)
    }
}

pub async fn establish(
    server: &ServerAddr,
    server_name: &str,
    skip_certificate_verification: bool,
    configured_alpn: Option<&[String]>,
    password: &str,
    up_mbps: Option<u64>,
    down_mbps: Option<u64>,
    salamander_password: Option<&str>,
    target: &Address,
    version: Version,
) -> io::Result<(SocketAddr, HysteriaStream)> {
    let remote = resolve_server(server).await?;
    let bind_addr = match remote.ip() {
        IpAddr::V4(_) => SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
        IpAddr::V6(_) => SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0),
    };

    let alpn = match (version, configured_alpn) {
        (Version::One, Some(values)) if !values.is_empty() => values.to_vec(),
        (Version::One, _) => vec!["hysteria".to_owned()],
        (Version::Two, _) => vec!["h3".to_owned()],
    };
    let mut tls = rustls_client_config_with_options(false, &alpn)?;
    if skip_certificate_verification {
        tls = rustls_client_config_with_options(true, &alpn)?;
    }
    let quic_crypto = QuicClientConfig::try_from(tls)
        .map_err(|err| io::Error::other(format!("hysteria QUIC TLS configuration: {err}")))?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_crypto));
    let mut transport = quinn::TransportConfig::default();
    transport
        .max_idle_timeout(Some(
            Duration::from_secs(30)
                .try_into()
                .map_err(|err| io::Error::other(format!("hysteria idle timeout: {err}")))?,
        ))
        .keep_alive_interval(Some(Duration::from_secs(10)));
    client_config.transport_config(Arc::new(transport));

    let mut endpoint = match salamander_password {
        Some(password) => salamander::endpoint(bind_addr, password),
        None => Endpoint::client(bind_addr),
    }
    .map_err(|err| io::Error::other(format!("hysteria UDP endpoint: {err}")))?;
    endpoint.set_default_client_config(client_config);
    let connection = endpoint
        .connect(remote, server_name)
        .map_err(|err| io::Error::other(format!("hysteria QUIC connect setup: {err}")))?
        .await
        .map_err(|err| io::Error::other(format!("hysteria QUIC connect: {err}")))?;

    let control = match version {
        Version::One => Some(authenticate_v1(&connection, password, up_mbps, down_mbps).await?),
        Version::Two => {
            authenticate_v2(&connection, password, down_mbps).await?;
            None
        }
    };

    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|err| io::Error::other(format!("hysteria open TCP stream: {err}")))?;
    match version {
        Version::One => write_tcp_request_v1(&mut send, target).await?,
        Version::Two => {
            write_varint(&mut send, HYSTERIA2_TCP_REQUEST).await?;
            write_tcp_request_v2(&mut send, target).await?;
        }
    }
    match version {
        Version::One => read_tcp_response_v1(&mut recv).await?,
        Version::Two => read_tcp_response_v2(&mut recv).await?,
    }

    let endpoint_addr = endpoint.local_addr()?;
    let local_addr = SocketAddr::new(
        connection.local_ip().unwrap_or(endpoint_addr.ip()),
        endpoint_addr.port(),
    );
    Ok((
        local_addr,
        HysteriaStream {
            send,
            recv,
            _control: control,
            _connection: connection,
            _endpoint: endpoint,
        },
    ))
}

async fn resolve_server(server: &ServerAddr) -> io::Result<SocketAddr> {
    match server {
        ServerAddr::SocketAddr(addr) => Ok(*addr),
        ServerAddr::DomainName(host, port) => tokio::net::lookup_host((host.as_str(), *port))
            .await?
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "hysteria server resolved to no addresses")),
    }
}

async fn authenticate_v1(
    connection: &quinn::Connection,
    password: &str,
    up_mbps: Option<u64>,
    down_mbps: Option<u64>,
) -> io::Result<(SendStream, RecvStream)> {
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|err| io::Error::other(format!("Hysteria 1 open control stream: {err}")))?;
    send.write_u8(HYSTERIA1_PROTOCOL_VERSION).await?;
    send.write_u64(up_mbps.unwrap_or(0).saturating_mul(125_000)).await?;
    send.write_u64(down_mbps.unwrap_or(0).saturating_mul(125_000)).await?;
    write_u16_bytes(&mut send, password.as_bytes(), "Hysteria 1 authentication").await?;
    send.flush().await?;

    let accepted = recv.read_u8().await? != 0;
    // Server TX/RX rates are used by the reference Brutal congestion
    // controller. Quinn's standard controller remains active for now, but
    // the fields must still be consumed to preserve control-stream framing.
    let _server_send_bps = recv.read_u64().await?;
    let _server_recv_bps = recv.read_u64().await?;
    let message = read_u16_string(&mut recv, "Hysteria 1 authentication response").await?;
    if !accepted {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("Hysteria 1 authentication rejected: {message}"),
        ));
    }
    Ok((send, recv))
}

async fn authenticate_v2(connection: &quinn::Connection, password: &str, down_mbps: Option<u64>) -> io::Result<()> {
    let (mut driver, mut sender) = h3::client::new(h3_quinn::Connection::new(connection.clone()))
        .await
        .map_err(|err| io::Error::other(format!("hysteria HTTP/3 setup: {err}")))?;
    tokio::spawn(async move {
        let _ = driver.wait_idle().await;
    });

    // Hysteria advertises bytes/second, while user-facing configuration is
    // expressed in megabits/second. Zero selects the server/default CC path.
    let receive_rate = down_mbps.unwrap_or(0).saturating_mul(125_000);
    let request = Request::post("https://hysteria/auth")
        .header("Hysteria-Auth", password)
        .header("Hysteria-CC-RX", receive_rate.to_string())
        .header("Hysteria-Padding", random_padding(256, 2048))
        .body(())
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, format!("hysteria auth request: {err}")))?;
    let mut stream = sender
        .send_request(request)
        .await
        .map_err(|err| io::Error::other(format!("hysteria auth send: {err}")))?;
    stream
        .finish()
        .await
        .map_err(|err| io::Error::other(format!("hysteria auth finish: {err}")))?;
    let response = stream
        .recv_response()
        .await
        .map_err(|err| io::Error::other(format!("hysteria auth response: {err}")))?;
    if response.status().as_u16() != AUTH_OK_STATUS {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("hysteria authentication rejected with status {}", response.status()),
        ));
    }

    // Dropping the final SendRequest gracefully closes the whole HTTP/3
    // connection. Keep it alive until the raw QUIC connection ends because
    // Hysteria opens its data streams outside HTTP/3.
    let keepalive = connection.clone();
    tokio::spawn(async move {
        let _sender = sender;
        let _ = keepalive.closed().await;
    });
    Ok(())
}

async fn write_tcp_request_v1<W>(send: &mut W, target: &Address) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let (host, port) = address_host_port(target);
    send.write_u8(0).await?;
    write_u16_bytes(send, host.as_bytes(), "Hysteria 1 target host").await?;
    send.write_u16(port).await?;
    send.flush().await
}

async fn read_tcp_response_v1<R>(recv: &mut R) -> io::Result<()>
where
    R: AsyncRead + Unpin,
{
    let accepted = recv.read_u8().await? != 0;
    let _udp_session_id = recv.read_u32().await?;
    let message = read_u16_string(recv, "Hysteria 1 TCP response").await?;
    if !accepted {
        return Err(io::Error::other(format!("Hysteria 1 TCP request rejected: {message}")));
    }
    Ok(())
}

async fn write_tcp_request_v2<W>(send: &mut W, target: &Address) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let address = target.to_string();
    if address.is_empty() || address.len() > 2048 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Hysteria target address length",
        ));
    }
    let padding = random_padding(64, 512);
    write_varint(send, address.len() as u64).await?;
    send.write_all(address.as_bytes()).await?;
    write_varint(send, padding.len() as u64).await?;
    send.write_all(padding.as_bytes()).await?;
    send.flush().await
}

async fn read_tcp_response_v2<R>(recv: &mut R) -> io::Result<()>
where
    R: AsyncRead + Unpin,
{
    let status = recv.read_u8().await?;
    let message_len = read_varint(recv).await?;
    if message_len > MAX_RESPONSE_FIELD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Hysteria response message is too large",
        ));
    }
    let mut message = vec![0; message_len as usize];
    AsyncReadExt::read_exact(recv, &mut message).await?;
    let padding_len = read_varint(recv).await?;
    if padding_len > MAX_RESPONSE_FIELD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Hysteria response padding is too large",
        ));
    }
    let mut padding = vec![0; padding_len as usize];
    AsyncReadExt::read_exact(recv, &mut padding).await?;
    if status != 0 {
        let message = String::from_utf8_lossy(&message);
        return Err(io::Error::other(format!("Hysteria TCP request rejected: {message}")));
    }
    Ok(())
}

fn address_host_port(target: &Address) -> (String, u16) {
    match target {
        Address::SocketAddress(addr) => (addr.ip().to_string(), addr.port()),
        Address::DomainNameAddress(host, port) => (host.clone(), *port),
    }
}

async fn write_u16_bytes<W>(writer: &mut W, value: &[u8], field: &str) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let length = u16::try_from(value.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, format!("{field} is too long")))?;
    writer.write_u16(length).await?;
    writer.write_all(value).await
}

async fn read_u16_string<R>(reader: &mut R, field: &str) -> io::Result<String>
where
    R: AsyncRead + Unpin,
{
    let length = reader.read_u16().await? as usize;
    if length > MAX_RESPONSE_FIELD as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{field} is too large"),
        ));
    }
    let mut value = vec![0; length];
    reader.read_exact(&mut value).await?;
    String::from_utf8(value).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

fn random_padding(min: usize, max: usize) -> String {
    let len = rand::rng().random_range(min..max);
    let mut bytes = vec![0u8; len];
    rand::rng().fill_bytes(&mut bytes);
    for byte in &mut bytes {
        *byte = PADDING_CHARS[*byte as usize % PADDING_CHARS.len()];
    }
    // PADDING_CHARS is ASCII.
    String::from_utf8(bytes).expect("ASCII padding")
}

async fn write_varint<W>(writer: &mut W, value: u64) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let encoded = encode_varint(value)?;
    writer.write_all(&encoded).await
}

fn encode_varint(value: u64) -> io::Result<Vec<u8>> {
    let len = if value <= 63 {
        1
    } else if value <= 16_383 {
        2
    } else if value <= 1_073_741_823 {
        4
    } else if value <= 4_611_686_018_427_387_903 {
        8
    } else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "value does not fit a QUIC varint",
        ));
    };
    let mut encoded = value.to_be_bytes()[8 - len..].to_vec();
    encoded[0] |= match len {
        1 => 0x00,
        2 => 0x40,
        4 => 0x80,
        8 => 0xc0,
        _ => unreachable!(),
    };
    Ok(encoded)
}

async fn read_varint<R>(reader: &mut R) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
{
    let first = reader.read_u8().await?;
    let len = 1usize << (first >> 6);
    let mut value = (first & 0x3f) as u64;
    for _ in 1..len {
        value = (value << 8) | reader.read_u8().await? as u64;
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quic_varints_match_wire_format() {
        assert_eq!(encode_varint(37).unwrap(), [37]);
        assert_eq!(encode_varint(15293).unwrap(), [0x7b, 0xbd]);
        assert_eq!(encode_varint(494878333).unwrap(), [0x9d, 0x7f, 0x3e, 0x7d]);
        assert_eq!(
            encode_varint(151288809941952652).unwrap(),
            [0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c]
        );
    }

    #[tokio::test]
    async fn quic_varint_round_trip() {
        for value in [0, 63, 64, 16_383, 16_384, 1_073_741_823, 1_073_741_824] {
            let encoded = encode_varint(value).unwrap();
            let mut bytes = encoded.as_slice();
            assert_eq!(read_varint(&mut bytes).await.unwrap(), value);
        }
    }

    #[tokio::test]
    async fn hysteria1_tcp_request_matches_reference_layout() {
        let (mut writer, mut reader) = tokio::io::duplex(64);
        let target = Address::DomainNameAddress("example.com".to_owned(), 443);
        let write = tokio::spawn(async move { write_tcp_request_v1(&mut writer, &target).await });
        let mut wire = [0u8; 1 + 2 + 11 + 2];
        reader.read_exact(&mut wire).await.unwrap();
        write.await.unwrap().unwrap();

        assert_eq!(wire[0], 0); // TCP, not UDP
        assert_eq!(&wire[1..3], &[0, 11]);
        assert_eq!(&wire[3..14], b"example.com");
        assert_eq!(&wire[14..], &443u16.to_be_bytes());
    }

    #[tokio::test]
    async fn hysteria1_tcp_response_consumes_all_fields() {
        let mut response = Vec::new();
        response.push(1);
        response.extend_from_slice(&0u32.to_be_bytes());
        response.extend_from_slice(&2u16.to_be_bytes());
        response.extend_from_slice(b"ok");
        read_tcp_response_v1(&mut response.as_slice()).await.unwrap();
    }
}
