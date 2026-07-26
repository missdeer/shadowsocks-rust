//! Minimal RFC 6455 client transport for proxy protocols.

use std::io;

use aws_lc_rs::digest::{SHA1_FOR_LEGACY_USE_ONLY, digest};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use rand::Rng;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf},
    sync::mpsc,
};

use super::stream::OutboundProxyStream;

const WS_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const MAX_HTTP_HEADER_SIZE: usize = 16 * 1024;
const MAX_FRAME_SIZE: u64 = 16 * 1024 * 1024;

pub async fn connect(mut stream: OutboundProxyStream, path: &str, host: &str) -> io::Result<DuplexStream> {
    let key_bytes: [u8; 16] = rand::random();
    let key = BASE64.encode(key_bytes);
    let path = if path.is_empty() { "/" } else { path };
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    let response = read_http_header(&mut stream).await?;
    validate_upgrade_response(&response, &key)?;

    let (application, worker) = tokio::io::duplex(64 * 1024);
    let (application_read, application_write) = tokio::io::split(worker);
    let (network_read, network_write) = tokio::io::split(stream);
    let (control_tx, control_rx) = mpsc::channel(8);

    tokio::spawn(websocket_write_loop(application_read, network_write, control_rx));
    tokio::spawn(websocket_read_loop(network_read, application_write, control_tx));
    Ok(application)
}

async fn read_http_header(stream: &mut OutboundProxyStream) -> io::Result<Vec<u8>> {
    let mut response = Vec::with_capacity(1024);
    while response.len() < MAX_HTTP_HEADER_SIZE {
        response.push(stream.read_u8().await?);
        if response.ends_with(b"\r\n\r\n") {
            return Ok(response);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "WebSocket upgrade response headers are too large",
    ))
}

fn validate_upgrade_response(response: &[u8], key: &str) -> io::Result<()> {
    let response = std::str::from_utf8(response)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "WebSocket upgrade response is not UTF-8"))?;
    let mut lines = response.split("\r\n");
    let status = lines.next().unwrap_or_default();
    if !status.starts_with("HTTP/1.1 101 ") && !status.starts_with("HTTP/1.0 101 ") {
        return Err(io::Error::other(format!("WebSocket upgrade failed: {status}")));
    }

    let mut accept = None;
    let mut connection_upgrade = false;
    let mut websocket_upgrade = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("sec-websocket-accept") {
            accept = Some(value);
        } else if name.eq_ignore_ascii_case("connection") {
            connection_upgrade = value.split(',').any(|part| part.trim().eq_ignore_ascii_case("upgrade"));
        } else if name.eq_ignore_ascii_case("upgrade") {
            websocket_upgrade = value.eq_ignore_ascii_case("websocket");
        }
    }

    let mut accept_input = key.as_bytes().to_vec();
    accept_input.extend_from_slice(WS_GUID);
    let expected = BASE64.encode(digest(&SHA1_FOR_LEGACY_USE_ONLY, &accept_input).as_ref());
    if accept != Some(expected.as_str()) || !connection_upgrade || !websocket_upgrade {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid WebSocket upgrade response",
        ));
    }
    Ok(())
}

enum ControlFrame {
    Pong(Vec<u8>),
    Close(Vec<u8>),
}

async fn websocket_write_loop(
    mut application: ReadHalf<DuplexStream>,
    mut network: WriteHalf<OutboundProxyStream>,
    mut control: mpsc::Receiver<ControlFrame>,
) {
    let mut data = vec![0u8; 16 * 1024];
    loop {
        let result = tokio::select! {
            biased;
            control = control.recv() => match control {
                Some(ControlFrame::Pong(payload)) => write_frame(&mut network, 0x0a, &payload).await,
                Some(ControlFrame::Close(payload)) => {
                    let _ = write_frame(&mut network, 0x08, &payload).await;
                    let _ = network.shutdown().await;
                    return;
                }
                None => return,
            },
            read = application.read(&mut data) => match read {
                Ok(0) => {
                    let _ = write_frame(&mut network, 0x08, &[]).await;
                    let _ = network.shutdown().await;
                    return;
                }
                Ok(len) => write_frame(&mut network, 0x02, &data[..len]).await,
                Err(_) => return,
            }
        };
        if result.is_err() {
            return;
        }
    }
}

async fn websocket_read_loop(
    mut network: ReadHalf<OutboundProxyStream>,
    mut application: WriteHalf<DuplexStream>,
    control: mpsc::Sender<ControlFrame>,
) {
    loop {
        let header = match read_frame_header(&mut network).await {
            Ok(header) => header,
            Err(_) => break,
        };
        let (opcode, length, mask) = header;
        match opcode {
            0x00 | 0x02 => {
                if copy_payload(&mut network, &mut application, length, mask)
                    .await
                    .is_err()
                {
                    break;
                }
            }
            0x08..=0x0a => {
                let payload = match read_payload(&mut network, length, mask).await {
                    Ok(payload) => payload,
                    Err(_) => break,
                };
                match opcode {
                    0x08 => {
                        let _ = control.send(ControlFrame::Close(payload)).await;
                        break;
                    }
                    0x09 if control.send(ControlFrame::Pong(payload)).await.is_err() => break,
                    _ => {}
                }
            }
            _ => {
                if discard_payload(&mut network, length).await.is_err() {
                    break;
                }
            }
        }
    }
    let _ = application.shutdown().await;
}

async fn read_frame_header<R>(reader: &mut R) -> io::Result<(u8, u64, Option<[u8; 4]>)>
where
    R: AsyncRead + Unpin,
{
    let first = reader.read_u8().await?;
    let second = reader.read_u8().await?;
    if first & 0x70 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported WebSocket RSV bits",
        ));
    }
    let opcode = first & 0x0f;
    let length = match second & 0x7f {
        length @ 0..=125 => length as u64,
        126 => reader.read_u16().await? as u64,
        127 => reader.read_u64().await?,
        _ => unreachable!(),
    };
    if length > MAX_FRAME_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "WebSocket frame is too large",
        ));
    }
    let mask = if second & 0x80 != 0 {
        let mut mask = [0u8; 4];
        reader.read_exact(&mut mask).await?;
        Some(mask)
    } else {
        None
    };
    Ok((opcode, length, mask))
}

async fn copy_payload<R, W>(reader: &mut R, writer: &mut W, mut remaining: u64, mask: Option<[u8; 4]>) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = [0u8; 8192];
    let mut offset = 0usize;
    while remaining > 0 {
        let length = remaining.min(buffer.len() as u64) as usize;
        reader.read_exact(&mut buffer[..length]).await?;
        if let Some(mask) = mask {
            for byte in &mut buffer[..length] {
                *byte ^= mask[offset % 4];
                offset += 1;
            }
        }
        writer.write_all(&buffer[..length]).await?;
        remaining -= length as u64;
    }
    writer.flush().await
}

async fn read_payload<R>(reader: &mut R, length: u64, mask: Option<[u8; 4]>) -> io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut payload = vec![0u8; length as usize];
    reader.read_exact(&mut payload).await?;
    if let Some(mask) = mask {
        for (offset, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[offset % 4];
        }
    }
    Ok(payload)
}

async fn discard_payload<R>(reader: &mut R, mut remaining: u64) -> io::Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut buffer = [0u8; 8192];
    while remaining > 0 {
        let length = remaining.min(buffer.len() as u64) as usize;
        reader.read_exact(&mut buffer[..length]).await?;
        remaining -= length as u64;
    }
    Ok(())
}

async fn write_frame<W>(writer: &mut W, opcode: u8, payload: &[u8]) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut header = [0u8; 14];
    header[0] = 0x80 | opcode;
    let mut header_len = 2;
    match payload.len() {
        0..=125 => header[1] = 0x80 | payload.len() as u8,
        126..=65535 => {
            header[1] = 0x80 | 126;
            header[2..4].copy_from_slice(&(payload.len() as u16).to_be_bytes());
            header_len = 4;
        }
        _ => {
            header[1] = 0x80 | 127;
            header[2..10].copy_from_slice(&(payload.len() as u64).to_be_bytes());
            header_len = 10;
        }
    }
    let mut mask = [0u8; 4];
    rand::rng().fill_bytes(&mut mask);
    header[header_len..header_len + 4].copy_from_slice(&mask);
    header_len += 4;

    writer.write_all(&header[..header_len]).await?;
    let mut masked = Vec::with_capacity(payload.len());
    masked.extend(payload.iter().enumerate().map(|(offset, byte)| byte ^ mask[offset % 4]));
    writer.write_all(&masked).await?;
    writer.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_a_websocket_upgrade() {
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let response = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
        validate_upgrade_response(response, key).unwrap();
    }
}
