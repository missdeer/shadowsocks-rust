//! VMess AEAD client protocol.
//!
//! The wire algorithm in this module is adapted from the MIT-licensed Shoes
//! project. See `crates/shadowsocks-service/LICENSE-SHOES`. It was rewritten
//! as a client-only, task-backed byte stream that composes with this crate's
//! existing primary-server and outbound-hop abstractions.

use std::{
    io,
    time::{SystemTime, UNIX_EPOCH},
};

use aws_lc_rs::{
    aead::{AES_128_GCM, Aad, BoundKey, CHACHA20_POLY1305, OpeningKey, SealingKey, UnboundKey},
    cipher::{AES_128, EncryptingKey as CipherEncryptingKey, EncryptionContext, UnboundCipherKey},
    digest::{Context, SHA256, digest},
};
use md5::{Digest as _, Md5};
use rand::{Rng, RngExt};
use shadowsocks::relay::socks5::Address;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf};

use super::{protocol::parse_uuid, stream::OutboundProxyStream};

const TAG_LEN: usize = 16;
const MAX_PLAINTEXT_CHUNK: usize = 8192;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DataCipher {
    Aes128Gcm,
    ChaCha20Poly1305,
    None,
}

impl DataCipher {
    fn parse(value: &str) -> io::Result<Self> {
        match value {
            "" | "auto" | "chacha20-poly1305" | "chacha20-ietf-poly1305" => Ok(Self::ChaCha20Poly1305),
            "aes-128-gcm" => Ok(Self::Aes128Gcm),
            "none" => Ok(Self::None),
            _ => Err(io::Error::new(io::ErrorKind::InvalidInput, "unsupported VMess cipher")),
        }
    }
}

pub async fn establish(
    mut stream: OutboundProxyStream,
    cipher: &str,
    uuid: &str,
    target: &Address,
) -> io::Result<DuplexStream> {
    let cipher = DataCipher::parse(cipher)?;
    let session = write_request_header(&mut stream, cipher, uuid, target).await?;
    let (application, worker) = tokio::io::duplex(64 * 1024);
    let (application_read, application_write) = tokio::io::split(worker);
    let (network_read, network_write) = tokio::io::split(stream);

    tokio::spawn(read_loop(network_read, application_write, session.reader));
    tokio::spawn(write_loop(application_read, network_write, session.writer));
    Ok(application)
}

struct Session {
    reader: ReaderState,
    writer: WriterState,
}

struct ReaderState {
    header_key: [u8; 16],
    header_iv: [u8; 16],
    response_auth: u8,
    key: Option<OpeningKey<VmessNonceSequence>>,
    length_mask: ShakeReader,
}

struct WriterState {
    key: Option<SealingKey<VmessNonceSequence>>,
    length_mask: ShakeReader,
}

async fn write_request_header(
    stream: &mut OutboundProxyStream,
    cipher: DataCipher,
    uuid: &str,
    target: &Address,
) -> io::Result<Session> {
    let uuid = parse_uuid(uuid)?;
    let mut instruction_material = Vec::with_capacity(52);
    instruction_material.extend_from_slice(&uuid);
    instruction_material.extend_from_slice(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
    let instruction_key = compute_md5(&instruction_material);

    let auth_key = kdf(&instruction_key, &[b"AES Auth ID Encryption"]);
    let auth_unbound = UnboundCipherKey::new(&AES_128, &auth_key[..16])
        .map_err(|_| io::Error::other("failed to create VMess auth key"))?;
    let auth_cipher =
        CipherEncryptingKey::ecb(auth_unbound).map_err(|_| io::Error::other("failed to create VMess auth cipher"))?;

    let random_delta = rand::rng().random_range(0..241u64);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| io::Error::other("system clock is before the Unix epoch"))?
        .as_secs();
    let timestamp = now.saturating_sub(120) + random_delta;
    let mut auth_id = [0u8; 16];
    auth_id[..8].copy_from_slice(&timestamp.to_be_bytes());
    rand::rng().fill_bytes(&mut auth_id[8..12]);
    let auth_checksum = crc32c(&auth_id[..12]).to_be_bytes();
    auth_id[12..].copy_from_slice(&auth_checksum);
    auth_cipher
        .less_safe_encrypt(&mut auth_id, EncryptionContext::None)
        .map_err(|_| io::Error::other("VMess auth ID encryption failed"))?;

    let mut header = [0u8; 316 + TAG_LEN];
    header[0] = 1;
    rand::rng().fill_bytes(&mut header[1..34]);
    let request_iv: [u8; 16] = header[1..17].try_into().unwrap();
    let request_key: [u8; 16] = header[17..33].try_into().unwrap();
    let response_auth = header[33];
    let response_iv: [u8; 16] = compute_sha256(&request_iv)[..16].try_into().unwrap();
    let response_key: [u8; 16] = compute_sha256(&request_key)[..16].try_into().unwrap();

    let (data_method, reader_key, writer_key) = match cipher {
        DataCipher::Aes128Gcm => (
            3,
            Some(OpeningKey::new(
                UnboundKey::new(&AES_128_GCM, &response_key).unwrap(),
                VmessNonceSequence::new(&response_iv),
            )),
            Some(SealingKey::new(
                UnboundKey::new(&AES_128_GCM, &request_key).unwrap(),
                VmessNonceSequence::new(&request_iv),
            )),
        ),
        DataCipher::ChaCha20Poly1305 => (
            4,
            Some(OpeningKey::new(
                UnboundKey::new(&CHACHA20_POLY1305, &create_chacha_key(&response_key)).unwrap(),
                VmessNonceSequence::new(&response_iv),
            )),
            Some(SealingKey::new(
                UnboundKey::new(&CHACHA20_POLY1305, &create_chacha_key(&request_key)).unwrap(),
                VmessNonceSequence::new(&request_iv),
            )),
        ),
        DataCipher::None => (5, None, None),
    };

    header[34] = 0x01 | 0x04; // chunk stream + chunk masking
    let margin_len = rand::random::<u8>() & 0x0f;
    header[35] = margin_len << 4 | data_method;
    header[37] = 1; // TCP
    let mut cursor = encode_target(target, &mut header)?;
    if margin_len != 0 {
        rand::rng().fill_bytes(&mut header[cursor..cursor + margin_len as usize]);
        cursor += margin_len as usize;
    }
    let checksum = fnv1a(&header[..cursor]);
    header[cursor..cursor + 4].copy_from_slice(&checksum.to_be_bytes());
    cursor += 4;

    let mut nonce = [0u8; 8];
    rand::rng().fill_bytes(&mut nonce);
    let length_key = kdf(&instruction_key, &[b"VMess Header AEAD Key_Length", &auth_id, &nonce]);
    let length_nonce = kdf(&instruction_key, &[b"VMess Header AEAD Nonce_Length", &auth_id, &nonce]);
    let mut encrypted_length = [0u8; 2 + TAG_LEN];
    encrypted_length[..2].copy_from_slice(&(cursor as u16).to_be_bytes());
    let mut length_sealer = SealingKey::new(
        UnboundKey::new(&AES_128_GCM, &length_key[..16]).unwrap(),
        SingleUseNonce::new(&length_nonce[..12]),
    );
    let tag = length_sealer
        .seal_in_place_separate_tag(Aad::from(&auth_id), &mut encrypted_length[..2])
        .map_err(|_| io::Error::other("failed to encrypt VMess header length"))?;
    encrypted_length[2..].copy_from_slice(tag.as_ref());

    let header_key = kdf(&instruction_key, &[b"VMess Header AEAD Key", &auth_id, &nonce]);
    let header_nonce = kdf(&instruction_key, &[b"VMess Header AEAD Nonce", &auth_id, &nonce]);
    let mut header_sealer = SealingKey::new(
        UnboundKey::new(&AES_128_GCM, &header_key[..16]).unwrap(),
        SingleUseNonce::new(&header_nonce[..12]),
    );
    let tag = header_sealer
        .seal_in_place_separate_tag(Aad::from(&auth_id), &mut header[..cursor])
        .map_err(|_| io::Error::other("failed to encrypt VMess request header"))?;
    header[cursor..cursor + TAG_LEN].copy_from_slice(tag.as_ref());
    cursor += TAG_LEN;

    let mut request = Vec::with_capacity(16 + encrypted_length.len() + nonce.len() + cursor);
    request.extend_from_slice(&auth_id);
    request.extend_from_slice(&encrypted_length);
    request.extend_from_slice(&nonce);
    request.extend_from_slice(&header[..cursor]);
    stream.write_all(&request).await?;
    stream.flush().await?;

    Ok(Session {
        reader: ReaderState {
            header_key: response_key,
            header_iv: response_iv,
            response_auth,
            key: reader_key,
            length_mask: ShakeReader::new(&response_iv),
        },
        writer: WriterState {
            key: writer_key,
            length_mask: ShakeReader::new(&request_iv),
        },
    })
}

fn encode_target(target: &Address, header: &mut [u8]) -> io::Result<usize> {
    header[38..40].copy_from_slice(&target.port().to_be_bytes());
    match target {
        Address::SocketAddress(addr) => match addr.ip() {
            std::net::IpAddr::V4(ip) => {
                header[40] = 1;
                header[41..45].copy_from_slice(&ip.octets());
                Ok(45)
            }
            std::net::IpAddr::V6(ip) => {
                header[40] = 3;
                header[41..57].copy_from_slice(&ip.octets());
                Ok(57)
            }
        },
        Address::DomainNameAddress(domain, _) => {
            if domain.len() > u8::MAX as usize {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "domain name is too long"));
            }
            header[40] = 2;
            header[41] = domain.len() as u8;
            header[42..42 + domain.len()].copy_from_slice(domain.as_bytes());
            Ok(42 + domain.len())
        }
    }
}

async fn read_loop(
    mut network: ReadHalf<OutboundProxyStream>,
    mut application: WriteHalf<DuplexStream>,
    mut state: ReaderState,
) {
    if read_response_header(&mut network, &state).await.is_err() {
        let _ = application.shutdown().await;
        return;
    }

    loop {
        let mut length_bytes = [0u8; 2];
        if network.read_exact(&mut length_bytes).await.is_err() {
            break;
        }
        let mut mask = [0u8; 2];
        state.length_mask.read(&mut mask);
        let length = u16::from_be_bytes(length_bytes) ^ u16::from_be_bytes(mask);
        let length = length as usize;
        let tag_len = if state.key.is_some() { TAG_LEN } else { 0 };
        if length < tag_len || length > u16::MAX as usize {
            break;
        }
        if length == tag_len {
            break;
        }
        let mut packet = vec![0u8; length];
        if network.read_exact(&mut packet).await.is_err() {
            break;
        }
        let plaintext = match state.key {
            Some(ref mut key) => match key.open_in_place(Aad::empty(), &mut packet) {
                Ok(plaintext) => plaintext,
                Err(_) => break,
            },
            None => packet.as_slice(),
        };
        if application.write_all(plaintext).await.is_err() || application.flush().await.is_err() {
            break;
        }
    }
    let _ = application.shutdown().await;
}

async fn read_response_header(network: &mut ReadHalf<OutboundProxyStream>, state: &ReaderState) -> io::Result<()> {
    let length_key = kdf(&state.header_key, &[b"AEAD Resp Header Len Key"]);
    let length_nonce = kdf(&state.header_iv, &[b"AEAD Resp Header Len IV"]);
    let mut encrypted_length = [0u8; 2 + TAG_LEN];
    network.read_exact(&mut encrypted_length).await?;
    let mut opener = OpeningKey::new(
        UnboundKey::new(&AES_128_GCM, &length_key[..16]).unwrap(),
        SingleUseNonce::new(&length_nonce[..12]),
    );
    let plaintext = opener
        .open_in_place(Aad::empty(), &mut encrypted_length)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid VMess response header length"))?;
    let length = u16::from_be_bytes(plaintext[..2].try_into().unwrap()) as usize;
    if !(4..=4096).contains(&length) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid VMess response header size",
        ));
    }

    let header_key = kdf(&state.header_key, &[b"AEAD Resp Header Key"]);
    let header_nonce = kdf(&state.header_iv, &[b"AEAD Resp Header IV"]);
    let mut encrypted_header = vec![0u8; length + TAG_LEN];
    network.read_exact(&mut encrypted_header).await?;
    let mut opener = OpeningKey::new(
        UnboundKey::new(&AES_128_GCM, &header_key[..16]).unwrap(),
        SingleUseNonce::new(&header_nonce[..12]),
    );
    let plaintext = opener
        .open_in_place(Aad::empty(), &mut encrypted_header)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid VMess response header"))?;
    if plaintext[0] != state.response_auth {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "VMess response authentication mismatch",
        ));
    }
    Ok(())
}

async fn write_loop(
    mut application: ReadHalf<DuplexStream>,
    mut network: WriteHalf<OutboundProxyStream>,
    mut state: WriterState,
) {
    let mut plaintext = vec![0u8; MAX_PLAINTEXT_CHUNK];
    loop {
        let length = match application.read(&mut plaintext).await {
            Ok(length) => length,
            Err(_) => return,
        };
        if write_packet(&mut network, &mut state, &plaintext[..length])
            .await
            .is_err()
        {
            return;
        }
        if length == 0 {
            let _ = network.shutdown().await;
            return;
        }
    }
}

async fn write_packet(
    network: &mut WriteHalf<OutboundProxyStream>,
    state: &mut WriterState,
    plaintext: &[u8],
) -> io::Result<()> {
    let mut packet = plaintext.to_vec();
    if let Some(ref mut key) = state.key {
        let tag = key
            .seal_in_place_separate_tag(Aad::empty(), &mut packet)
            .map_err(|_| io::Error::other("failed to encrypt VMess data"))?;
        packet.extend_from_slice(tag.as_ref());
    }
    let mut mask = [0u8; 2];
    state.length_mask.read(&mut mask);
    let masked_length = (packet.len() as u16) ^ u16::from_be_bytes(mask);
    network.write_all(&masked_length.to_be_bytes()).await?;
    network.write_all(&packet).await?;
    network.flush().await
}

/// Small SHAKE128 reader specialized for VMess's 16-byte IV seed.
struct ShakeReader {
    state: [u64; 25],
    offset: usize,
}

impl ShakeReader {
    const RATE: usize = 168;

    fn new(seed: &[u8]) -> Self {
        let mut block = [0u8; Self::RATE];
        block[..seed.len()].copy_from_slice(seed);
        block[seed.len()] ^= 0x1f;
        block[Self::RATE - 1] ^= 0x80;

        let mut state = [0u64; 25];
        for (lane, bytes) in state.iter_mut().zip(block.chunks_exact(8)) {
            *lane ^= u64::from_le_bytes(bytes.try_into().unwrap());
        }
        keccak_f1600(&mut state);
        Self { state, offset: 0 }
    }

    fn read(&mut self, output: &mut [u8]) {
        for byte in output {
            if self.offset == Self::RATE {
                keccak_f1600(&mut self.state);
                self.offset = 0;
            }
            *byte = (self.state[self.offset / 8] >> (8 * (self.offset % 8))) as u8;
            self.offset += 1;
        }
    }
}

fn keccak_f1600(state: &mut [u64; 25]) {
    const ROUND_CONSTANTS: [u64; 24] = [
        0x0000_0000_0000_0001,
        0x0000_0000_0000_8082,
        0x8000_0000_0000_808a,
        0x8000_0000_8000_8000,
        0x0000_0000_0000_808b,
        0x0000_0000_8000_0001,
        0x8000_0000_8000_8081,
        0x8000_0000_0000_8009,
        0x0000_0000_0000_008a,
        0x0000_0000_0000_0088,
        0x0000_0000_8000_8009,
        0x0000_0000_8000_000a,
        0x0000_0000_8000_808b,
        0x8000_0000_0000_008b,
        0x8000_0000_0000_8089,
        0x8000_0000_0000_8003,
        0x8000_0000_0000_8002,
        0x8000_0000_0000_0080,
        0x0000_0000_0000_800a,
        0x8000_0000_8000_000a,
        0x8000_0000_8000_8081,
        0x8000_0000_0000_8080,
        0x0000_0000_8000_0001,
        0x8000_0000_8000_8008,
    ];
    const ROTATIONS: [u32; 24] = [
        1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
    ];
    const PERMUTATION: [usize; 24] = [
        10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
    ];

    for round_constant in ROUND_CONSTANTS {
        let mut columns = [0u64; 5];
        for x in 0..5 {
            columns[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        for x in 0..5 {
            let delta = columns[(x + 4) % 5] ^ columns[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                state[x + 5 * y] ^= delta;
            }
        }

        let mut current = state[1];
        for (&target, &rotation) in PERMUTATION.iter().zip(&ROTATIONS) {
            let next = state[target];
            state[target] = current.rotate_left(rotation);
            current = next;
        }

        for y in 0..5 {
            let row: [u64; 5] = state[y * 5..y * 5 + 5].try_into().unwrap();
            for x in 0..5 {
                state[y * 5 + x] = row[x] ^ ((!row[(x + 1) % 5]) & row[(x + 2) % 5]);
            }
        }
        state[0] ^= round_constant;
    }
}

struct VmessNonceSequence {
    count: u16,
    nonce: [u8; 12],
}

impl VmessNonceSequence {
    fn new(data: &[u8]) -> Self {
        let mut nonce = [0u8; 12];
        nonce[2..].copy_from_slice(&data[2..12]);
        Self { count: 0, nonce }
    }
}

impl aws_lc_rs::aead::NonceSequence for VmessNonceSequence {
    fn advance(&mut self) -> Result<aws_lc_rs::aead::Nonce, aws_lc_rs::error::Unspecified> {
        let nonce = aws_lc_rs::aead::Nonce::assume_unique_for_key(self.nonce);
        self.count = self.count.wrapping_add(1);
        self.nonce[..2].copy_from_slice(&self.count.to_be_bytes());
        Ok(nonce)
    }
}

struct SingleUseNonce(Option<[u8; 12]>);

impl SingleUseNonce {
    fn new(data: &[u8]) -> Self {
        Self(Some(data.try_into().expect("nonce must contain 12 bytes")))
    }
}

impl aws_lc_rs::aead::NonceSequence for SingleUseNonce {
    fn advance(&mut self) -> Result<aws_lc_rs::aead::Nonce, aws_lc_rs::error::Unspecified> {
        let nonce = self.0.take().expect("single-use nonce reused");
        aws_lc_rs::aead::Nonce::try_assume_unique_for_key(&nonce)
    }
}

trait VmessHash: std::fmt::Debug {
    fn setup_new(&self) -> Box<dyn VmessHash>;
    fn update(&mut self, data: &[u8]);
    fn finalize(&mut self) -> [u8; 32];
}

struct Sha256Hash(Context);

impl std::fmt::Debug for Sha256Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Sha256Hash").field(&"Context").finish()
    }
}

impl VmessHash for Sha256Hash {
    fn setup_new(&self) -> Box<dyn VmessHash> {
        Box::new(Self(self.0.clone()))
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn finalize(&mut self) -> [u8; 32] {
        self.0.clone().finish().as_ref().try_into().unwrap()
    }
}

#[derive(Debug)]
struct RecursiveHash {
    inner: Box<dyn VmessHash>,
    outer: Box<dyn VmessHash>,
    default_inner: [u8; 64],
    default_outer: [u8; 64],
}

impl RecursiveHash {
    fn new(key: &[u8], hash: Box<dyn VmessHash>) -> Self {
        let mut default_inner = [0x36; 64];
        let mut default_outer = [0x5c; 64];
        for (offset, byte) in key.iter().enumerate() {
            default_inner[offset] ^= byte;
            default_outer[offset] ^= byte;
        }
        let mut inner = hash.setup_new();
        inner.update(&default_inner);
        Self {
            inner,
            outer: hash,
            default_inner,
            default_outer,
        }
    }
}

impl VmessHash for RecursiveHash {
    fn setup_new(&self) -> Box<dyn VmessHash> {
        Box::new(Self {
            inner: self.inner.setup_new(),
            outer: self.outer.setup_new(),
            default_inner: self.default_inner,
            default_outer: self.default_outer,
        })
    }

    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finalize(&mut self) -> [u8; 32] {
        self.outer.update(&self.default_outer);
        self.outer.update(&self.inner.finalize());
        self.outer.finalize()
    }
}

fn kdf(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
    let mut current: Box<dyn VmessHash> = Box::new(RecursiveHash::new(
        b"VMess AEAD KDF",
        Box::new(Sha256Hash(Context::new(&SHA256))),
    ));
    for item in path {
        current = Box::new(RecursiveHash::new(item, current));
    }
    current.update(key);
    current.finalize()
}

fn compute_sha256(data: &[u8]) -> [u8; 32] {
    digest(&SHA256, data).as_ref().try_into().unwrap()
}

fn compute_md5(data: &[u8]) -> [u8; 16] {
    let mut md5 = Md5::new();
    md5::Digest::update(&mut md5, data);
    md5.finalize().into()
}

fn create_chacha_key(data: &[u8]) -> [u8; 32] {
    let first = compute_md5(data);
    let second = compute_md5(&first);
    let mut key = [0u8; 32];
    key[..16].copy_from_slice(&first);
    key[16..].copy_from_slice(&second);
    key
}

fn fnv1a(data: &[u8]) -> u32 {
    data.iter().fold(0x811c9dc5u32, |hash, byte| {
        (hash ^ *byte as u32).wrapping_mul(16_777_619)
    })
}

fn crc32c(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in data {
        crc ^= *byte as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xedb8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_helpers_match_known_vectors() {
        assert_eq!(fnv1a(b"hello"), 0x4f9f2cab);
        assert_eq!(crc32c(b""), 0);
        assert_eq!(
            compute_md5(b"hello"),
            [
                0x5d, 0x41, 0x40, 0x2a, 0xbc, 0x4b, 0x2a, 0x76, 0xb9, 0x71, 0x9d, 0x91, 0x10, 0x17, 0xc5, 0x92
            ]
        );
    }

    #[test]
    fn kdf_is_deterministic() {
        assert_eq!(kdf(b"key", &[b"path"]), kdf(b"key", &[b"path"]));
    }

    #[test]
    fn shake128_matches_known_empty_vector() {
        let mut reader = ShakeReader::new(&[]);
        let mut output = [0u8; 32];
        reader.read(&mut output);
        assert_eq!(
            output,
            [
                0x7f, 0x9c, 0x2b, 0xa4, 0xe8, 0x8f, 0x82, 0x7d, 0x61, 0x60, 0x45, 0x50, 0x76, 0x05, 0x85, 0x3e, 0xd7,
                0x3b, 0x80, 0x93, 0xf6, 0xef, 0xbc, 0x88, 0xeb, 0x1a, 0x6e, 0xac, 0xfa, 0x66, 0xef, 0x26,
            ]
        );
    }
}
