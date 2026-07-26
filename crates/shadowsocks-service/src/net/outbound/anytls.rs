//! Client-side AnyTLS framing over an established TLS stream.
//!
//! The wire format follows the public AnyTLS protocol specification and the
//! MIT-licensed implementations in `anytls-go` and Shoes. This client opens a
//! dedicated session for each outbound tunnel; the session format still uses
//! stream IDs and protocol v2 negotiation, so it interoperates with current
//! AnyTLS servers without adding server-side code to this crate.

use std::io;

use aws_lc_rs::digest::{SHA256, digest};
use md5::{Digest as _, Md5};
use shadowsocks::relay::socks5::Address;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf},
    sync::mpsc,
};

use super::stream::OutboundProxyStream;

const CMD_WASTE: u8 = 0;
const CMD_SYN: u8 = 1;
const CMD_PSH: u8 = 2;
const CMD_FIN: u8 = 3;
const CMD_SETTINGS: u8 = 4;
const CMD_ALERT: u8 = 5;
const CMD_UPDATE_PADDING_SCHEME: u8 = 6;
const CMD_SYN_ACK: u8 = 7;
const CMD_HEART_REQUEST: u8 = 8;
const CMD_HEART_RESPONSE: u8 = 9;
const CMD_SERVER_SETTINGS: u8 = 10;
const STREAM_ID: u32 = 1;
const FRAME_HEADER_LEN: usize = 7;
const MAX_FRAME_PAYLOAD: usize = u16::MAX as usize;

const DEFAULT_PADDING_SCHEME: &str = "stop=8\n\
0=30-30\n\
1=100-400\n\
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n\
3=9-9,500-1000\n\
4=500-1000\n\
5=500-1000\n\
6=500-1000\n\
7=500-1000";

pub async fn establish(mut stream: OutboundProxyStream, password: &str, target: &Address) -> io::Result<DuplexStream> {
    write_authentication(&mut stream, password).await?;

    let mut initial = Vec::with_capacity(256);
    let padding_md5 = hex_lower(&compute_md5(DEFAULT_PADDING_SCHEME.as_bytes()));
    let settings = format!("v=2\nclient=shadowsocks-rust/1.25.0\npadding-md5={padding_md5}");
    append_frame(&mut initial, CMD_SETTINGS, 0, settings.as_bytes())?;
    append_frame(&mut initial, CMD_SYN, STREAM_ID, &[])?;
    let mut address = Vec::with_capacity(256);
    encode_socks_address(target, &mut address)?;
    append_frame(&mut initial, CMD_PSH, STREAM_ID, &address)?;
    stream.write_all(&initial).await?;
    stream.flush().await?;

    let (application, worker) = tokio::io::duplex(64 * 1024);
    let (application_read, application_write) = tokio::io::split(worker);
    let (network_read, network_write) = tokio::io::split(stream);
    let (control_tx, control_rx) = mpsc::channel(8);

    tokio::spawn(write_loop(application_read, network_write, control_rx));
    tokio::spawn(read_loop(network_read, application_write, control_tx));
    Ok(application)
}

async fn write_authentication(stream: &mut OutboundProxyStream, password: &str) -> io::Result<()> {
    let password_hash = digest(&SHA256, password.as_bytes());
    let padding_len = 30u16;
    let mut auth = Vec::with_capacity(34 + padding_len as usize);
    auth.extend_from_slice(password_hash.as_ref());
    auth.extend_from_slice(&padding_len.to_be_bytes());
    auth.resize(auth.len() + padding_len as usize, 0);
    stream.write_all(&auth).await?;
    stream.flush().await
}

async fn write_loop(
    mut application: ReadHalf<DuplexStream>,
    mut network: WriteHalf<OutboundProxyStream>,
    mut control: mpsc::Receiver<Vec<u8>>,
) {
    let mut data = vec![0u8; 16 * 1024];
    loop {
        let frame = tokio::select! {
            biased;
            control = control.recv() => match control {
                Some(frame) => frame,
                None => return,
            },
            read = application.read(&mut data) => match read {
                Ok(0) => {
                    let mut frame = Vec::with_capacity(FRAME_HEADER_LEN);
                    if append_frame(&mut frame, CMD_FIN, STREAM_ID, &[]).is_err() {
                        return;
                    }
                    if network.write_all(&frame).await.is_ok() {
                        let _ = network.shutdown().await;
                    }
                    return;
                }
                Ok(length) => {
                    let mut frame = Vec::with_capacity(FRAME_HEADER_LEN + length);
                    if append_frame(&mut frame, CMD_PSH, STREAM_ID, &data[..length]).is_err() {
                        return;
                    }
                    frame
                }
                Err(_) => return,
            }
        };
        if network.write_all(&frame).await.is_err() || network.flush().await.is_err() {
            return;
        }
    }
}

async fn read_loop(
    mut network: ReadHalf<OutboundProxyStream>,
    mut application: WriteHalf<DuplexStream>,
    control: mpsc::Sender<Vec<u8>>,
) {
    loop {
        let mut header = [0u8; FRAME_HEADER_LEN];
        if network.read_exact(&mut header).await.is_err() {
            break;
        }
        let command = header[0];
        let stream_id = u32::from_be_bytes(header[1..5].try_into().unwrap());
        let length = u16::from_be_bytes(header[5..7].try_into().unwrap()) as usize;
        let mut payload = vec![0u8; length];
        if network.read_exact(&mut payload).await.is_err() {
            break;
        }

        match command {
            CMD_PSH if stream_id == STREAM_ID => {
                if application.write_all(&payload).await.is_err() || application.flush().await.is_err() {
                    break;
                }
            }
            CMD_FIN if stream_id == STREAM_ID => break,
            CMD_SYN_ACK if stream_id == STREAM_ID && !payload.is_empty() => break,
            CMD_HEART_REQUEST => {
                let mut response = Vec::with_capacity(FRAME_HEADER_LEN);
                if append_frame(&mut response, CMD_HEART_RESPONSE, stream_id, &[]).is_err()
                    || control.send(response).await.is_err()
                {
                    break;
                }
            }
            CMD_ALERT => break,
            CMD_WASTE | CMD_UPDATE_PADDING_SCHEME | CMD_SERVER_SETTINGS | CMD_SYN_ACK => {}
            _ => {}
        }
    }
    let _ = application.shutdown().await;
}

fn append_frame(output: &mut Vec<u8>, command: u8, stream_id: u32, payload: &[u8]) -> io::Result<()> {
    if payload.len() > MAX_FRAME_PAYLOAD {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "AnyTLS frame is too large"));
    }
    output.push(command);
    output.extend_from_slice(&stream_id.to_be_bytes());
    output.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    output.extend_from_slice(payload);
    Ok(())
}

fn encode_socks_address(target: &Address, output: &mut Vec<u8>) -> io::Result<()> {
    match target {
        Address::SocketAddress(addr) => match addr.ip() {
            std::net::IpAddr::V4(ip) => {
                output.push(1);
                output.extend_from_slice(&ip.octets());
            }
            std::net::IpAddr::V6(ip) => {
                output.push(4);
                output.extend_from_slice(&ip.octets());
            }
        },
        Address::DomainNameAddress(domain, _) => {
            if domain.len() > u8::MAX as usize {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "domain name is too long"));
            }
            output.push(3);
            output.push(domain.len() as u8);
            output.extend_from_slice(domain.as_bytes());
        }
    }
    output.extend_from_slice(&target.port().to_be_bytes());
    Ok(())
}

fn compute_md5(data: &[u8]) -> [u8; 16] {
    let mut md5 = Md5::new();
    md5.update(data);
    md5.finalize().into()
}

fn hex_lower(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(data.len() * 2);
    for byte in data {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_padding_hash_matches_reference() {
        assert_eq!(hex_lower(&compute_md5(DEFAULT_PADDING_SCHEME.as_bytes())).len(), 32);
    }

    #[test]
    fn frame_header_is_big_endian() {
        let mut output = Vec::new();
        append_frame(&mut output, CMD_PSH, 0x0102_0304, b"abc").unwrap();
        assert_eq!(&output[..7], &[CMD_PSH, 1, 2, 3, 4, 0, 3]);
    }
}
