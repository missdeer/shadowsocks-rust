//! Client-side REALITY transport.
//!
//! The TLS 1.3/REALITY state machine in this directory is adapted from the
//! MIT-licensed `shoes` project. Only its client-side core and buffer helpers
//! are vendored; the async bridge and integration with this project's static
//! outbound stream are implemented here. See `LICENSE-SHOES` at repository
//! root for attribution.

#![allow(dead_code)]

use std::io::{self, Read as _, Write as _};

use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

use super::stream::OutboundProxyStream;
use super::{protocol::build_vless_request, vision::VisionStream};
use shadowsocks::relay::socks5::Address;

mod buf_reader;
mod common;
mod reality_aead;
mod reality_auth;
#[cfg(test)]
mod reality_certificate;
mod reality_cipher_suite;
mod reality_client_connection;
mod reality_client_verify;
mod reality_io_state;
mod reality_reader_writer;
mod reality_records;
mod reality_tls13_keys;
mod reality_tls13_messages;
mod reality_util;
mod slide_buffer;

use reality_client_connection::RealityClientConfig;
pub(super) use reality_client_connection::{RealityClientConnection, feed_reality_client_connection};
use reality_util::{decode_public_key, decode_short_id};

const BRIDGE_CAPACITY: usize = 64 * 1024;
const IO_BUFFER_SIZE: usize = 32 * 1024;

#[inline]
#[allow(clippy::uninit_vec)]
pub(super) fn allocate_vec<T>(len: usize) -> Vec<T> {
    let mut value = Vec::with_capacity(len);
    // This helper is retained from the vendored implementation. Every call
    // site immediately initializes the allocated byte storage before reading.
    unsafe { value.set_len(len) };
    value
}

pub async fn establish(
    stream: OutboundProxyStream,
    server_name: &str,
    public_key: &str,
    short_id: &str,
) -> io::Result<DuplexStream> {
    let config = RealityClientConfig {
        public_key: decode_public_key(public_key)?,
        short_id: decode_short_id(short_id)?,
        server_name: server_name.to_owned(),
        cipher_suites: Vec::new(),
    };
    let session = RealityClientConnection::new(config)?;
    let (stream, session) = handshake(stream, session).await?;

    let (client, bridge) = tokio::io::duplex(BRIDGE_CAPACITY);
    tokio::spawn(async move {
        if let Err(err) = run_bridge(stream, session, bridge).await {
            log::debug!("REALITY transport ended: {err}");
        }
    });
    Ok(client)
}

pub async fn establish_vision(
    stream: OutboundProxyStream,
    server_name: &str,
    public_key: &str,
    short_id: &str,
    uuid: &str,
    target: &Address,
) -> io::Result<VisionStream<Box<OutboundProxyStream>>> {
    let config = RealityClientConfig {
        public_key: decode_public_key(public_key)?,
        short_id: decode_short_id(short_id)?,
        server_name: server_name.to_owned(),
        cipher_suites: Vec::new(),
    };
    let session = RealityClientConnection::new(config)?;
    let (mut stream, mut session) = handshake(stream, session).await?;
    let (uuid, request) = build_vless_request(uuid, Some("xtls-rprx-vision"), target)?;
    session.writer().write_all(&request)?;
    drain_encrypted(&mut session, &mut stream).await?;
    stream.flush().await?;
    Ok(VisionStream::new_client(Box::new(stream), session, uuid))
}

async fn handshake(
    mut stream: OutboundProxyStream,
    mut session: RealityClientConnection,
) -> io::Result<(OutboundProxyStream, RealityClientConnection)> {
    let mut incoming = vec![0u8; IO_BUFFER_SIZE];
    while session.is_handshaking() {
        drain_encrypted(&mut session, &mut stream).await?;
        if !session.is_handshaking() {
            break;
        }
        let size = stream.read(&mut incoming).await?;
        if size == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "REALITY peer closed during handshake",
            ));
        }
        feed_reality_client_connection(&mut session, &incoming[..size])?;
        session.process_new_packets()?;
    }
    drain_encrypted(&mut session, &mut stream).await?;
    stream.flush().await?;
    Ok((stream, session))
}

async fn run_bridge(
    mut network: OutboundProxyStream,
    mut session: RealityClientConnection,
    bridge: DuplexStream,
) -> io::Result<()> {
    let (mut application_read, mut application_write) = tokio::io::split(bridge);
    let mut application_open = true;
    let mut application_buffer = vec![0u8; IO_BUFFER_SIZE];
    let mut network_buffer = vec![0u8; IO_BUFFER_SIZE];

    loop {
        tokio::select! {
            result = application_read.read(&mut application_buffer), if application_open => {
                let size = result?;
                if size == 0 {
                    application_open = false;
                    session.send_close_notify();
                    drain_encrypted(&mut session, &mut network).await?;
                    network.flush().await?;
                } else {
                    session.writer().write_all(&application_buffer[..size])?;
                    drain_encrypted(&mut session, &mut network).await?;
                }
            }
            result = network.read(&mut network_buffer) => {
                let size = result?;
                if size == 0 {
                    application_write.shutdown().await?;
                    return Ok(());
                }
                feed_reality_client_connection(&mut session, &network_buffer[..size])?;
                let state = session.process_new_packets()?;
                let available = state.plaintext_bytes_to_read();
                if available != 0 {
                    let mut plaintext = vec![0u8; available];
                    session.reader().read_exact(&mut plaintext)?;
                    application_write.write_all(&plaintext).await?;
                    application_write.flush().await?;
                }
                // TLS 1.3 post-handshake messages may generate a response.
                drain_encrypted(&mut session, &mut network).await?;
            }
        }
    }
}

async fn drain_encrypted(session: &mut RealityClientConnection, stream: &mut OutboundProxyStream) -> io::Result<()> {
    while session.wants_write() {
        let mut encrypted = Vec::with_capacity(IO_BUFFER_SIZE);
        let size = session.write_tls(&mut encrypted)?;
        if size == 0 {
            break;
        }
        stream.write_all(&encrypted).await?;
    }
    Ok(())
}
