//! Hysteria 2 Salamander per-datagram obfuscation.

use std::{
    fmt,
    io::{self, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use blake2::{Blake2b, Digest, digest::consts::U32};
use quinn::{
    AsyncUdpSocket, Endpoint, EndpointConfig, Runtime, TokioRuntime, UdpPoller,
    udp::{RecvMeta, Transmit},
};
use rand::Rng;

const SALT_LEN: usize = 8;
const KEY_LEN: usize = 32;
type Blake2b256 = Blake2b<U32>;

pub fn endpoint(bind_addr: SocketAddr, password: &str) -> io::Result<Endpoint> {
    if password.len() < 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Hysteria 2 salamander password must be at least 4 bytes",
        ));
    }
    let socket = std::net::UdpSocket::bind(bind_addr)?;
    socket.set_nonblocking(true)?;
    let runtime: Arc<dyn Runtime> = Arc::new(TokioRuntime);
    let inner = runtime.wrap_udp_socket(socket)?;
    let socket: Arc<dyn AsyncUdpSocket> = Arc::new(SalamanderSocket {
        inner,
        password: password.as_bytes().to_vec().into_boxed_slice(),
        send_buffer: Mutex::new(Vec::with_capacity(64 * 1024)),
    });
    Endpoint::new_with_abstract_socket(EndpointConfig::default(), None, socket, runtime)
}

struct SalamanderSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    password: Box<[u8]>,
    send_buffer: Mutex<Vec<u8>>,
}

impl fmt::Debug for SalamanderSocket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("SalamanderSocket").finish_non_exhaustive()
    }
}

impl AsyncUdpSocket for SalamanderSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        let segment_size = transmit.segment_size.unwrap_or(transmit.contents.len());
        let mut output = self
            .send_buffer
            .lock()
            .map_err(|_| io::Error::other("salamander lock poisoned"))?;
        output.clear();
        for segment in transmit.contents.chunks(segment_size) {
            let mut salt = [0u8; SALT_LEN];
            rand::rng().fill_bytes(&mut salt);
            let key = derive_key(&self.password, &salt);
            output.extend_from_slice(&salt);
            output.extend(
                segment
                    .iter()
                    .enumerate()
                    .map(|(index, byte)| byte ^ key[index % KEY_LEN]),
            );
        }
        self.inner.try_send(&Transmit {
            destination: transmit.destination,
            ecn: transmit.ecn,
            contents: &output,
            segment_size: transmit.segment_size.map(|size| size + SALT_LEN),
            src_ip: transmit.src_ip,
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        buffers: &mut [IoSliceMut<'_>],
        metadata: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let count = match self.inner.poll_recv(cx, buffers, metadata) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Ready(Ok(count)) => count,
        };
        for (buffer, meta) in buffers.iter_mut().zip(metadata.iter_mut()).take(count) {
            if !deobfuscate_datagrams(&self.password, &mut buffer[..meta.len], meta) {
                // Invalid or unrelated UDP datagrams are consumed and exposed
                // as empty entries; Quinn safely ignores zero-length metadata.
                meta.len = 0;
                meta.stride = 0;
            }
        }
        Poll::Ready(Ok(count))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

fn deobfuscate_datagrams(password: &[u8], buffer: &mut [u8], meta: &mut RecvMeta) -> bool {
    let wire_stride = if meta.stride == 0 { meta.len } else { meta.stride };
    if wire_stride <= SALT_LEN {
        return false;
    }
    let mut source = 0usize;
    let mut destination = 0usize;
    let mut first_plaintext_len = None;
    while source < meta.len {
        let wire_len = wire_stride.min(meta.len - source);
        if wire_len <= SALT_LEN {
            return false;
        }
        let plaintext_len = wire_len - SALT_LEN;
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&buffer[source..source + SALT_LEN]);
        let key = derive_key(password, &salt);
        for index in 0..plaintext_len {
            buffer[destination + index] = buffer[source + SALT_LEN + index] ^ key[index % KEY_LEN];
        }
        first_plaintext_len.get_or_insert(plaintext_len);
        source += wire_len;
        destination += plaintext_len;
    }
    meta.len = destination;
    meta.stride = first_plaintext_len.unwrap_or(0);
    true
}

fn derive_key(password: &[u8], salt: &[u8; SALT_LEN]) -> [u8; KEY_LEN] {
    let mut digest = Blake2b256::new();
    digest.update(password);
    digest.update(salt);
    digest.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn official_wire_shape_round_trips() {
        let password = b"average_password";
        let salt = *b"12345678";
        let plaintext = b"a QUIC packet";
        let key = derive_key(password, &salt);
        let mut wire = Vec::from(salt);
        wire.extend(
            plaintext
                .iter()
                .enumerate()
                .map(|(index, byte)| byte ^ key[index % KEY_LEN]),
        );
        let mut meta = RecvMeta {
            len: wire.len(),
            stride: wire.len(),
            ..RecvMeta::default()
        };
        assert!(deobfuscate_datagrams(password, &mut wire, &mut meta));
        assert_eq!(&wire[..meta.len], plaintext);
    }

    #[test]
    fn rejects_short_datagrams() {
        let mut wire = [0u8; SALT_LEN];
        let mut meta = RecvMeta {
            len: wire.len(),
            stride: wire.len(),
            ..RecvMeta::default()
        };
        assert!(!deobfuscate_datagrams(b"password", &mut wire, &mut meta));
    }

    #[test]
    fn gro_segments_are_deobfuscated_and_compacted() {
        let password = b"average_password";
        let plaintext_segments: [&[u8]; 2] = [b"first packet", b"second packe"];
        let salts = [*b"12345678", *b"abcdefgh"];
        let wire_stride = SALT_LEN + plaintext_segments[0].len();
        let mut wire = Vec::with_capacity(wire_stride * plaintext_segments.len());
        for (plaintext, salt) in plaintext_segments.into_iter().zip(salts) {
            let key = derive_key(password, &salt);
            wire.extend_from_slice(&salt);
            wire.extend(
                plaintext
                    .iter()
                    .enumerate()
                    .map(|(index, byte)| byte ^ key[index % KEY_LEN]),
            );
        }
        let mut meta = RecvMeta {
            len: wire.len(),
            stride: wire_stride,
            ..RecvMeta::default()
        };

        assert!(deobfuscate_datagrams(password, &mut wire, &mut meta));
        assert_eq!(meta.stride, plaintext_segments[0].len());
        assert_eq!(
            meta.len,
            plaintext_segments.iter().map(|segment| segment.len()).sum::<usize>()
        );
        assert_eq!(&wire[..meta.len], b"first packetsecond packe");
    }
}
