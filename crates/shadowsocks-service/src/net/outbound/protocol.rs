//! Client-side primary proxy protocol handshakes.
//!
//! This module intentionally contains no server implementation. Protocols
//! transform an already-established byte stream into a tunnel to `target`;
//! the existing chain builder can then negotiate unchanged `outbound_proxy`
//! hops on top of that tunnel.

use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};

use aws_lc_rs::digest::{SHA224, digest};
use shadowsocks::relay::socks5::Address;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::stream::OutboundProxyStream;

const COMMAND_TCP: u8 = 1;

pub async fn establish_vless(
    mut stream: OutboundProxyStream,
    uuid: &str,
    flow: Option<&str>,
    target: &Address,
) -> io::Result<VlessClientStream> {
    let (_, request) = build_vless_request(uuid, flow, target)?;

    stream.write_all(&request).await?;
    stream.flush().await?;
    Ok(VlessClientStream::new(stream))
}

pub(super) fn build_vless_request(uuid: &str, flow: Option<&str>, target: &Address) -> io::Result<([u8; 16], Vec<u8>)> {
    let uuid = parse_uuid(uuid)?;
    let addons = match flow {
        None | Some("") => Vec::new(),
        Some(flow) => encode_vless_flow(flow)?,
    };

    if addons.len() > u8::MAX as usize {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "VLESS addons are too long"));
    }

    let mut request = Vec::with_capacity(22 + addons.len() + 256);
    request.push(0); // protocol version
    request.extend_from_slice(&uuid);
    request.push(addons.len() as u8);
    request.extend_from_slice(&addons);
    request.push(COMMAND_TCP);
    encode_vless_address(target, &mut request)?;
    Ok((uuid, request))
}

pub async fn establish_trojan(
    mut stream: OutboundProxyStream,
    password: &str,
    target: &Address,
) -> io::Result<OutboundProxyStream> {
    let password_hash = digest(&SHA224, password.as_bytes());
    let mut request = Vec::with_capacity(64 + 256);
    for byte in password_hash.as_ref() {
        use std::fmt::Write;
        write!(&mut StringByteWriter(&mut request), "{byte:02x}").expect("writing to a Vec cannot fail");
    }
    request.extend_from_slice(b"\r\n");
    request.push(COMMAND_TCP);
    encode_socks_address(target, &mut request)?;
    request.extend_from_slice(b"\r\n");

    stream.write_all(&request).await?;
    stream.flush().await?;
    Ok(stream)
}

struct StringByteWriter<'a>(&'a mut Vec<u8>);

impl std::fmt::Write for StringByteWriter<'_> {
    fn write_str(&mut self, value: &str) -> std::fmt::Result {
        self.0.extend_from_slice(value.as_bytes());
        Ok(())
    }
}

pub(super) fn parse_uuid(value: &str) -> io::Result<[u8; 16]> {
    let mut uuid = [0u8; 16];
    let mut high_nibble = None;
    let mut cursor = 0usize;

    for byte in value.bytes() {
        if byte == b'-' {
            continue;
        }
        let nibble = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid UUID")),
        };
        match high_nibble.take() {
            Some(high) if cursor < uuid.len() => {
                uuid[cursor] = high << 4 | nibble;
                cursor += 1;
            }
            Some(_) => return Err(io::Error::new(io::ErrorKind::InvalidInput, "UUID is too long")),
            None => high_nibble = Some(nibble),
        }
    }

    if cursor != uuid.len() || high_nibble.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "UUID must contain 16 bytes",
        ));
    }
    Ok(uuid)
}

fn encode_vless_flow(flow: &str) -> io::Result<Vec<u8>> {
    if flow.len() > 127 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "VLESS flow name is too long",
        ));
    }
    let mut addons = Vec::with_capacity(flow.len() + 2);
    addons.push(0x0a); // protobuf field 1, length-delimited
    addons.push(flow.len() as u8);
    addons.extend_from_slice(flow.as_bytes());
    Ok(addons)
}

fn encode_vless_address(target: &Address, output: &mut Vec<u8>) -> io::Result<()> {
    output.extend_from_slice(&target.port().to_be_bytes());
    match target {
        Address::SocketAddress(addr) => match addr.ip() {
            std::net::IpAddr::V4(ip) => {
                output.push(1);
                output.extend_from_slice(&ip.octets());
            }
            std::net::IpAddr::V6(ip) => {
                output.push(3);
                output.extend_from_slice(&ip.octets());
            }
        },
        Address::DomainNameAddress(domain, _) => {
            if domain.len() > u8::MAX as usize {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "domain name is too long"));
            }
            output.push(2);
            output.push(domain.len() as u8);
            output.extend_from_slice(domain.as_bytes());
        }
    }
    Ok(())
}

fn encode_socks_address(target: &Address, output: &mut Vec<u8>) -> io::Result<()> {
    match target {
        Address::SocketAddress(addr) => match addr.ip() {
            std::net::IpAddr::V4(ip) => {
                output.push(1);
                output.extend_from_slice(&ip.octets());
                output.extend_from_slice(&addr.port().to_be_bytes());
            }
            std::net::IpAddr::V6(ip) => {
                output.push(4);
                output.extend_from_slice(&ip.octets());
                output.extend_from_slice(&addr.port().to_be_bytes());
            }
        },
        Address::DomainNameAddress(domain, port) => {
            if domain.len() > u8::MAX as usize {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "domain name is too long"));
            }
            output.push(3);
            output.push(domain.len() as u8);
            output.extend_from_slice(domain.as_bytes());
            output.extend_from_slice(&port.to_be_bytes());
        }
    }
    Ok(())
}

/// VLESS leaves a small response header in front of the target byte stream.
/// It is consumed lazily because a server normally sends it only after the
/// client has written application data.
pub struct VlessClientStream {
    inner: Box<OutboundProxyStream>,
    response_header: [u8; 257],
    response_filled: usize,
    response_needed: usize,
}

impl VlessClientStream {
    fn new(inner: OutboundProxyStream) -> Self {
        Self {
            inner: Box::new(inner),
            response_header: [0; 257],
            response_filled: 0,
            response_needed: 2,
        }
    }

    fn poll_response_header(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.response_filled < self.response_needed {
            let mut read_buf = ReadBuf::new(&mut self.response_header[self.response_filled..self.response_needed]);
            ready!(Pin::new(&mut self.inner).poll_read(cx, &mut read_buf))?;
            if read_buf.filled().is_empty() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed while reading VLESS response header",
                )));
            }
            self.response_filled += read_buf.filled().len();
            if self.response_filled >= 2 && self.response_needed == 2 {
                if self.response_header[0] != 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unsupported VLESS response version",
                    )));
                }
                self.response_needed = 2 + self.response_header[1] as usize;
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for VlessClientStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if self.response_needed != 0 {
            ready!(self.poll_response_header(cx))?;
            self.response_needed = 0;
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for VlessClientStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_uuid_with_or_without_dashes() {
        let expected = parse_uuid("550e8400-e29b-41d4-a716-446655440000").unwrap();
        assert_eq!(expected, parse_uuid("550e8400e29b41d4a716446655440000").unwrap());
        assert!(parse_uuid("not-a-uuid").is_err());
    }

    #[test]
    fn encodes_vless_domain_address() {
        let mut output = Vec::new();
        encode_vless_address(&Address::DomainNameAddress("example.com".to_owned(), 443), &mut output).unwrap();
        assert_eq!(&output[..4], &[0x01, 0xbb, 0x02, 11]);
        assert_eq!(&output[4..], b"example.com");
    }

    #[test]
    fn encodes_trojan_socks_address() {
        let mut output = Vec::new();
        encode_socks_address(&Address::DomainNameAddress("example.com".to_owned(), 443), &mut output).unwrap();
        assert_eq!(&output[..2], &[0x03, 11]);
        assert_eq!(&output[2..13], b"example.com");
        assert_eq!(&output[13..], &[0x01, 0xbb]);
    }
}
