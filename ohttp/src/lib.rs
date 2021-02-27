#![deny(clippy::pedantic)]
#![allow(clippy::missing_errors_doc)] // I'm too lazy

mod err;
// mod nss;
mod rw;

use log::trace;

pub use err::Error;
// pub use nss::hpke::{AeadId, KdfId, KemId};

use err::Res;
// use nss::aead::{Aead, Mode, NONCE_LEN};
// use nss::hkdf::{Hkdf, KeyMechanism};
// use nss::hpke::{Hpke, HpkeConfig};
// use nss::{random, PrivateKey, PublicKey};

use aes_gcm::aead::{generic_array::GenericArray, Key, Nonce, AeadInPlace, NewAead};
use aes_gcm::Aes128Gcm;
use hkdf::Hkdf;
use sha2::Sha256;

use rw::{read_uint, read_uvec, write_uint, write_uvec};
use std::cmp::max;
use std::convert::TryFrom;
use std::io::{BufReader, Read};
use std::mem::size_of;

use hpke::{
    aead::{AeadTag, AesGcm128},
    kdf::HkdfSha256,
    kem::X25519HkdfSha256,
    kex::KeyExchange,
    Deserializable, EncappedKey, Kem as KemTrait, OpModeR, OpModeS, Serializable,
    AeadCtxR, 
    AeadCtxS,
};

const KEM_ID: u16 = 0x0020;
const KDF_ID: u16 = 0x0001;
const AEAD_ID: u16 = 0x0001;

use rand::{rngs::StdRng, SeedableRng};

// These are the only algorithms we're gonna use for this example
type Kem = X25519HkdfSha256;
type Aead = AesGcm128;
type Kdf = HkdfSha256;

type PrivateKey = <Kex as KeyExchange>::PrivateKey;
type PublicKey = <Kex as KeyExchange>::PublicKey;

// The KEX is dependent on the choice of KEM
type Kex = <Kem as KemTrait>::Kex;

const INFO_REQUEST: &[u8] = b"request";
const LABEL_RESPONSE: &[u8] = b"response";
const INFO_KEY: &[u8] = b"key";
const INFO_NONCE: &[u8] = b"nonce";

/// The type of a key identifier.
pub type KeyId = u8;

pub fn init() {
    // nss::init();
    let _ = env_logger::try_init();
}

// /// A tuple of KDF and AEAD identifiers.
// #[derive(Debug, Copy, Clone, PartialEq, Eq)]
// pub struct SymmetricSuite {
//     // kdf: KdfId::Type,
//     kdf: u16,
//     // aead: AeadId::Type,
//     aead: u16,
// }

// impl SymmetricSuite {
//     #[must_use]
//     pub const fn new(kdf: u16, aead: u16) -> Self {
//         Self { kdf, aead }
//     }

//     #[must_use]
//     pub fn kdf(self) -> u16 {
//         self.kdf
//     }

//     #[must_use]
//     pub fn aead(self) -> u16 {
//         self.aead
//     }
// }

/// The key configuration of a server.  This can be used by both client and server.
/// An important invariant of this structure is that it does not include
/// any combination of KEM, KDF, and AEAD that is not supported.
pub struct KeyConfig {
    key_id: KeyId,
    // kem: KemId::Type,
    // kem: Kem,
    // symmetric: Vec<SymmetricSuite>,
    sk: Option<PrivateKey>,
    pk: PublicKey,
}

impl KeyConfig {
    // fn strip_unsupported(symmetric: &mut Vec<SymmetricSuite>, kem: u16) {
        // TODO(caw): fixme
        // symmetric.retain(|s| HpkeConfig::new(kem, s.kdf(), s.aead()).supported());
    // }

    /// Construct a configuration for the server side.
    /// Panics if the configurations don't include a supported configuration.
    pub fn new(key_id: u8) -> Res<Self> {
        // Self::strip_unsupported(&mut symmetric, kem.KEM_ID);
        // assert!(!symmetric.is_empty());
        // assert!(kem == KEM_ID);

        let mut csprng = StdRng::from_entropy();
        let (sk, pk) = Kem::gen_keypair(&mut csprng);

        // let cfg = HpkeConfig::new(kem, symmetric[0].kdf(), symmetric[0].aead());
        // let (sk, pk) = Hpke::new(cfg)?.generate_key_pair()?;
        Ok(Self {
            key_id,
            // kem,
            // symmetric,
            sk: Some(sk),
            pk,
        })
    }

    /// Encode into a wire format.  This shares a format with the core of ECH:
    ///
    /// ```tls-format
    /// opaque HpkePublicKey<1..2^16-1>;
    /// uint16 HpkeKemId;  // Defined in I-D.irtf-cfrg-hpke
    /// uint16 HpkeKdfId;  // Defined in I-D.irtf-cfrg-hpke
    /// uint16 HpkeAeadId; // Defined in I-D.irtf-cfrg-hpke
    ///
    /// struct {
    ///   HpkeKdfId kdf_id;
    ///   HpkeAeadId aead_id;
    /// } ECHCipherSuite;
    ///
    /// struct {
    ///   uint8 key_id;
    ///   HpkeKemId kem_id;
    ///   HpkePublicKey public_key;
    ///   ECHCipherSuite cipher_suites<4..2^16-4>;
    /// } ECHKeyConfig;
    /// ```
    pub fn encode(&self) -> Res<Vec<u8>> {
        let mut buf = Vec::new();
        write_uint(size_of::<KeyId>(), self.key_id, &mut buf)?;
        write_uint(2, KEM_ID, &mut buf)?;
        // let pk_buf = self.pk.key_data()?;
        let mut pk_buf = self.pk.to_bytes().as_slice().to_vec();
        write_uvec(2, &pk_buf, &mut buf)?;
        write_uint(
            2,
            u16::try_from(1 * 4).unwrap(),
            &mut buf,
        )?;
        write_uint(2, KDF_ID, &mut buf)?;
        write_uint(2, AEAD_ID, &mut buf)?;
        // for s in &self.symmetric {
        //     write_uint(2, s.kdf(), &mut buf)?;
        //     write_uint(2, s.aead(), &mut buf)?;
        // }
        Ok(buf)
    }

    /// Construct a configuration from the encoded server configuration.
    /// The format of `encoded_config` is the output of `Self::encode`.
    fn parse(encoded_config: &[u8]) -> Res<Self> {
        let mut r = BufReader::new(encoded_config);
        let key_id = KeyId::try_from(read_uint(size_of::<KeyId>(), &mut r)?).unwrap();
    
        let kem_id = read_uint(2, &mut r)? as u16;
        assert!(kem_id == KEM_ID);

        let pk_buf = read_uvec(2, &mut r)?;
        let sym = read_uvec(2, &mut r)?;
        if sym.is_empty() || (sym.len() % 4 != 0) {
            return Err(Error::Format);
        }
        let sym_count = sym.len() / 4;
        let mut sym_r = BufReader::new(&sym[..]);
        // let mut symmetric = Vec::with_capacity(sym_count);
        for _ in 0..sym_count {            
            // let kdf = KdfId::Type::try_from(read_uint(2, &mut sym_r)?).unwrap();
            let kdf_id = read_uint(2, &mut sym_r)? as u16;
            assert!(kdf_id == KDF_ID);

            // let aead = hpke::AEAD_ID::try_from(read_uint(2, &mut sym_r)?).unwrap();
            let aead_id = read_uint(2, &mut sym_r)? as u16;
            assert!(aead_id == AEAD_ID);
            // symmetric.push(SymmetricSuite::new(HkdfSha256{}, AesGcm128{}));
        }
        
        // Check that there was nothing extra.
        let mut tmp = [0; 1];
        if r.read(&mut tmp)? > 0 {
            return Err(Error::Format);
        }

        // Self::strip_unsupported(&mut symmetric, KEM_ID);
        // let hpke = Hpke::new(HpkeConfig::new(
        //     kem,
        //     symmetric[0].kdf(),  // KDF doesn't matter here
        //     symmetric[0].aead(), // ditto
        // ))?;
        // let pk = hpke.decode_public_key(&pk_buf)?;

        let pk = <Kex as KeyExchange>::PublicKey::from_bytes(&pk_buf).unwrap();
        Ok(Self {
            key_id,
            // X25519HkdfSha256,
            // symmetric,
            sk: None,
            pk,
        })
    }

    // fn create_hpke(&mut self, sym: SymmetricSuite) -> Res<Hpke> {
    //     if self.symmetric.contains(&sym) {
    //         let config = HpkeConfig::new(self.kem, sym.kdf(), sym.aead());
    //         Ok(Hpke::new(config)?)
    //     } else {
    //         Err(Error::Unsupported)
    //     }
    // }
}

/// This is the sort of information we expect to receive from the receiver.
/// This might not be necessary if we agree on a format.
#[cfg(feature = "client")]
pub struct ClientRequest {
    key_id: KeyId,
    // hpke: Hpke,
    enc: EncappedKey::<Kex>,
    sender_ctx: AeadCtxS<Aead, Kdf, Kem>,
}

impl ClientRequest {
    /// Reads an encoded configuration and constructs a single use client sender.
    /// See `KeyConfig::encode` for the structure details.
    #[allow(clippy::similar_names)] // for `sk_s` and `pk_s`
    pub fn new(encoded_config: &[u8]) -> Res<Self> {
        let mut csprng = StdRng::from_entropy();
        let mut config = KeyConfig::parse(encoded_config)?;

        // TODO(mt) choose the best config, not just the first.
        // let mut hpke = config.create_hpke(config.symmetric[0])?;

        // Result<(EncappedKey<Kem::Kex>, AeadCtxS<A, Kdf, Kem>), HpkeError>
        let (enc, mut sender_ctx) = hpke::setup_sender::<Aead, Kdf, Kem, _>(&OpModeS::Base, &config.pk, INFO_REQUEST, &mut csprng).unwrap();
        // let (mut sk_s, pk_s) = hpke.generate_key_pair()?;
        // hpke.setup_s(&pk_s, &mut sk_s, &mut config.pk, INFO_REQUEST)?;

        Ok(Self {
            key_id: config.key_id,
            // hpke,
            enc,
            sender_ctx,
        })
    }

    /// Encapsulate a request.  This consumes this object.
    /// This produces a response handler and the bytes of an encapsulated request.
    pub fn encapsulate(mut self, request: &[u8]) -> Res<(Vec<u8>, ClientResponse)> {
        // AAD is keyID + kdfID + aeadID:
        let mut enc_request = Vec::new();
        write_uint(size_of::<KeyId>(), self.key_id, &mut enc_request)?;
        // write_uint(2, self.hpke.kdf(), &mut enc_request)?;
        // write_uint(2, self.hpke.aead(), &mut enc_request)?;
        write_uint(2, KDF_ID, &mut enc_request)?;
        write_uint(2, AEAD_ID, &mut enc_request)?;

        // let mut ct = self.hpke.seal(&enc_request, request)?;
        // let enc = self.hpke.enc()?;
        let mut request_copy = request.to_vec();
        let tag = self.sender_ctx.seal(&mut request_copy, &enc_request).unwrap();

        let mut tag_bytes = tag.to_bytes().as_slice().to_vec();
        let encapped_key_bytes = self.enc.to_bytes().as_slice().to_vec();

        enc_request.extend_from_slice(&encapped_key_bytes);
        enc_request.append(&mut request_copy);
        enc_request.append(&mut tag_bytes);
        Ok((enc_request, ClientResponse::new(self.sender_ctx, encapped_key_bytes)))
    }
}

/// A server can handle multiple requests.
/// It holds a single key pair and can generate a configuration.
/// (A more complex server would have multiple key pairs. This is simple.)
#[cfg(feature = "server")]
pub struct Server {
    config: KeyConfig,
}

impl Server {
    /// Create a new server configuration.
    /// Panics if the configuration doesn't include a private key.
    pub fn new(config: KeyConfig) -> Res<Self> {
        assert!(config.sk.is_some());
        Ok(Self { config })
    }

    /// Get the configuration that this server uses.
    #[must_use]
    pub fn config(&self) -> &KeyConfig {
        &self.config
    }

    pub fn decapsulate(&mut self, enc_request: &[u8]) -> Res<(Vec<u8>, ServerResponse)> {
        const AAD_LEN: usize = size_of::<KeyId>() + 4;
        if enc_request.len() < AAD_LEN {
            return Err(Error::Truncated);
        }
        let aad = &enc_request[..AAD_LEN];
        let mut r = BufReader::new(enc_request);
        let key_id = u8::try_from(read_uint(size_of::<KeyId>(), &mut r)?).unwrap();
        if key_id != self.config.key_id {
            return Err(Error::KeyId);
        }

        let kdf_id = read_uint(2, &mut r)? as u16;
        assert!(kdf_id == KDF_ID);
        let aead_id = read_uint(2, &mut r)? as u16;
        assert!(aead_id == AEAD_ID);
        // let sym = SymmetricSuite::new(HkdfSha256{}, AesGcm128{});

        let mut enc = vec![0; 32]; // TODO(caw): fixme
        r.read_exact(&mut enc)?;

        let encapped_key = EncappedKey::<Kex>::from_bytes(&enc).unwrap();

        match &self.config.sk {
            Some(sk) => {
                let mut receiver_ctx = hpke::setup_receiver::<Aead, Kdf, Kem>(&OpModeR::Base, &sk, &encapped_key, INFO_REQUEST).unwrap();
                let mut rest = Vec::new();
                r.read_to_end(&mut rest)?;
                let (mut ct_vec, mut tag_vec) = rest.split_at(rest.len() - 16);
                
                let tag = AeadTag::<Aead>::from_bytes(tag_vec).unwrap();
                let mut request = ct_vec.to_vec();
                receiver_ctx.open(&mut request, aad, &tag).unwrap();
        
                // let request = hpke.open(aad, &ct)?;
        
                Ok((request, ServerResponse::new(receiver_ctx, enc)?))   
            }
            _ => Err(Error::KeyId)
        }
    }
}

// fn entropy(config: HpkeConfig) -> usize {
//     max(config.n_n(), config.n_k())
// }

fn make_aead(secret: &[u8], enc: Vec<u8>, response_nonce: &[u8]) -> Res<(Aes128Gcm, Vec<u8>)> {
    let mut salt = enc;
    salt.extend_from_slice(response_nonce);

    let (prk, hk) = Hkdf::<Sha256>::extract(Some(&salt), &secret);
    // let mut okm = [0u8; 42];
    
    // let hkdf = Hkdf::new(hpke.config().kdf());
    // let prk = hkdf.extract(&salt, &secret)?;

    let mut key = [0u8; 16];
    hk.expand(INFO_KEY, &mut key);

    let mut iv = [0u8; 12];
    hk.expand(INFO_NONCE, &mut iv);

    // let key = hkdf.expand_key(&prk, INFO_KEY, KeyMechanism::Aead(hpke.config().aead()))?;
    // let iv = hkdf.expand_data(&prk, INFO_NONCE, hpke.config().n_n())?;
    // let nonce_base = <[u8; NONCE_LEN]>::try_from(iv).unwrap();

    // Ok(Aead::new(mode, hpke.config().aead(), &key, nonce_base)?)

    let nonce = iv.to_vec();
    let cipher = Aes128Gcm::new(GenericArray::from_slice(&key));
    Ok((cipher, nonce))
}

fn make_response_aead(ctx: AeadCtxR<Aead, Kdf, Kem>, enc: Vec<u8>, response_nonce: &[u8]) -> Res<(Aes128Gcm, Vec<u8>)> {
    let mut secret = [0u8; 16]; 
    ctx.export(LABEL_RESPONSE, &mut secret).unwrap();
    make_aead(&secret, enc, response_nonce)
}

fn make_sender_aead(ctx: AeadCtxS<Aead, Kdf, Kem>, enc: Vec<u8>, response_nonce: &[u8]) -> Res<(Aes128Gcm, Vec<u8>)> {
    let mut secret = [0u8; 16]; 
    ctx.export(LABEL_RESPONSE, &mut secret).unwrap();
    make_aead(&secret, enc, response_nonce)
}

/// An object for encapsulating responses.
/// The only way to obtain one of these is through `Server::decapsulate()`.
#[cfg(feature = "server")]
pub struct ServerResponse {
    response_nonce: Vec<u8>,
    // aead: Aead,
    aead: Aes128Gcm,
    nonce: Vec<u8>,
}

impl ServerResponse {
    fn new(ctx: AeadCtxR<Aead, Kdf, Kem>, enc: Vec<u8>) -> Res<Self> {
        // let response_nonce = random(entropy(hpke.config()));
        let response_nonce = [0u8; 16]; // TODO(caw): fixme
        let (aead, nonce) = make_response_aead(ctx, enc, &response_nonce)?;
        Ok(Self {
            response_nonce: response_nonce.to_vec(),
            aead: aead,
            nonce: nonce,
        })
    }

    /// Consume this object by encapsulating a response.
    pub fn encapsulate(mut self, response: &[u8]) -> Res<Vec<u8>> {
        let mut enc_response = self.response_nonce;
        
        let mut response_copy = response.to_owned();
        self.aead.encrypt_in_place(GenericArray::from_slice(&self.nonce), &[], &mut response_copy).unwrap();
        // let mut ct = self.aead.seal(&[], response)?;
        enc_response.append(&mut response_copy);
        Ok(enc_response)
    }
}

/// An object for decapsulating responses.
/// The only way to obtain one of these is through `ClientRequest::encapsulate()`.
#[cfg(feature = "client")]
pub struct ClientResponse {
    // hpke: Hpke,
    ctx: AeadCtxS<Aead, Kdf, Kem>,
    enc: Vec<u8>,
}

impl ClientResponse {
    /// Private method for constructing one of these.
    /// Doesn't do anything because we don't have the nonce yet, so
    /// the work that can be done is limited.
    fn new(ctx: AeadCtxS<Aead, Kdf, Kem>, enc: Vec<u8>) -> Self {
        Self { ctx, enc }
    }

    /// Consume this object by decapsulating a response.
    pub fn decapsulate(self, enc_response: &[u8]) -> Res<Vec<u8>> {
        let entropy_len = 16;
        let (response_nonce, ct) = enc_response.split_at(entropy_len);
        let (aead, nonce) = make_sender_aead(self.ctx, self.enc, response_nonce)?;

        let mut data = ct.to_owned();
        aead.decrypt_in_place(GenericArray::from_slice(&nonce), &[], &mut data).unwrap();
        Ok(data.to_vec())
        // Ok(aead.open(&[], 0, ct)?) // 0 is the sequence number
    }
}

#[cfg(all(test, feature = "client", feature = "server"))]
mod test {
    // use crate::nss::hpke::{AeadId, KdfId, KemId};
    use crate::{ClientRequest, KeyConfig, KeyId, Server};
    use log::trace;

    const KEY_ID: KeyId = 1;
    // const KEM: hpke::KEM_ID = KEM_ID;
    // const SYMMETRIC: &[SymmetricSuite] = &[
        // SymmetricSuite::new(KDF_ID, AEAD_ID),
    // ];

    const REQUEST: &[u8] = &[
        0x00, 0x03, 0x47, 0x45, 0x54, 0x05, 0x68, 0x74, 0x74, 0x70, 0x73, 0x0b, 0x65, 0x78, 0x61,
        0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x01, 0x2f,
    ];
    const RESPONSE: &[u8] = &[0x01, 0x40, 0xc8];

    #[test]
    fn request_response() {
        // crate::init();

        let server_config = KeyConfig::new(KEY_ID).unwrap();
        let mut server = Server::new(server_config).unwrap();
        let encoded_config = server.config().encode().unwrap();
        trace!("Config: {}", hex::encode(&encoded_config));

        let recovered_config = KeyConfig::parse(&encoded_config).unwrap();

        let client = ClientRequest::new(&encoded_config).unwrap();
        let (enc_request, client_response) = client.encapsulate(REQUEST).unwrap();
        trace!("Request: {}", hex::encode(REQUEST));
        trace!("Encapsulated Request: {}", hex::encode(&enc_request));

        let (request, server_response) = server.decapsulate(&enc_request).unwrap();
        assert_eq!(&request[..], REQUEST);

        let enc_response = server_response.encapsulate(RESPONSE).unwrap();
        trace!("Encapsulated Response: {}", hex::encode(&enc_response));

        let response = client_response.decapsulate(&enc_response).unwrap();
        assert_eq!(&response[..], RESPONSE);
        trace!("Response: {}", hex::encode(RESPONSE));
    }

    // #[test]
    // fn two_requests() {
    //     crate::init();

    //     let server_config = KeyConfig::new(KEY_ID, KEM, Vec::from(SYMMETRIC)).unwrap();
    //     let mut server = Server::new(server_config).unwrap();
    //     let encoded_config = server.config().encode().unwrap();

    //     let client1 = ClientRequest::new(&encoded_config).unwrap();
    //     let (enc_request1, client_response1) = client1.encapsulate(REQUEST).unwrap();
    //     let client2 = ClientRequest::new(&encoded_config).unwrap();
    //     let (enc_request2, client_response2) = client2.encapsulate(REQUEST).unwrap();
    //     assert_ne!(enc_request1, enc_request2);

    //     let (request1, server_response1) = server.decapsulate(&enc_request1).unwrap();
    //     assert_eq!(&request1[..], REQUEST);
    //     let (request2, server_response2) = server.decapsulate(&enc_request2).unwrap();
    //     assert_eq!(&request2[..], REQUEST);

    //     let enc_response1 = server_response1.encapsulate(RESPONSE).unwrap();
    //     let enc_response2 = server_response2.encapsulate(RESPONSE).unwrap();
    //     assert_ne!(enc_response1, enc_response2);

    //     let response1 = client_response1.decapsulate(&enc_response1).unwrap();
    //     assert_eq!(&response1[..], RESPONSE);
    //     let response2 = client_response2.decapsulate(&enc_response2).unwrap();
    //     assert_eq!(&response2[..], RESPONSE);
    // }
}
