//! Define the notary file format

use mina_curves::pasta::Fp;
use mina_hasher::{Hashable, ROInput};
use mina_signer::{signature::Signature, Keypair, Signer};

use crate::ZkOraclesVersion;

/// Row data of a notarization file.
#[derive(Clone)]
pub struct NotaryFileRawData {
    // Commitment of client key share using Poseidon-based commitment.
    pub client_key_share_commitment: Fp,

    // Notary key share with 128-bit string.
    pub notary_key_share: [u8; 16],

    // The length of the encrypted query.
    pub encrypted_query_length: u32,

    // The encrypted qurey that will be sent to the server.
    pub encrypted_query: Vec<u8>,

    // The IV of the encrypted query, this is specified to AES-GCM.
    pub encrypted_query_iv: [u8; 12],

    // The length of the encrypted response.
    pub encrypted_response_length: u32,

    // The encrypted response sent by the server.
    pub encrypted_response: Vec<u8>,

    // The IV of the encrypted response, this is specified to AES-GCM
    pub encrypted_response_iv: [u8; 12],

    // The URL address of the server.
    pub server_address: Vec<u8>,

    // The time_stamp of this notarization file. E.g., 20221113
    pub time_stamp: u64,

    // The validity period of this file. E.g., 1000(days)
    pub validity_period: u64,
}
impl NotaryFileRawData {
    pub fn new(
        client_key_share_commitment: Fp,
        notary_key_share: [u8; 16],
        encrypted_query_length: u32,
        encrypted_query: Vec<u8>,
        encrypted_query_iv: [u8; 12],
        encrypted_response_length: u32,
        encrypted_response: Vec<u8>,
        encrypted_response_iv: [u8; 12],
        server_address: Vec<u8>,
        time_stamp: u64,
        validity_period: u64,
    ) -> Self {
        Self {
            client_key_share_commitment,
            notary_key_share,
            encrypted_query_length,
            encrypted_query,
            encrypted_query_iv,
            encrypted_response_length,
            encrypted_response,
            encrypted_response_iv,
            server_address,
            time_stamp,
            validity_period,
        }
    }
}

impl Hashable for NotaryFileRawData {
    type D = ZkOraclesVersion;

    fn to_roinput(&self) -> ROInput {
        ROInput::new()
            .append_field(self.client_key_share_commitment)
            .append_bytes(self.notary_key_share.as_slice())
            .append_u32(self.encrypted_query_length)
            .append_bytes(&self.encrypted_query)
            .append_bytes(self.encrypted_query_iv.as_slice())
            .append_u32(self.encrypted_response_length)
            .append_bytes(&self.encrypted_response)
            .append_bytes(self.encrypted_response_iv.as_slice())
            .append_bytes(&self.server_address)
            .append_u64(self.time_stamp)
            .append_u64(self.validity_period)
    }

    fn domain_string(_: Self::D) -> Option<String> {
        None
    }
}

/// Structure of a notarization file, including the signature signed by the Notary.
#[derive(Clone)]
pub struct NotaryFile {
    pub raw_data: NotaryFileRawData,
    pub sig: Option<Signature>,
}

impl NotaryFile {
    pub fn new(raw_data: NotaryFileRawData) -> Self {
        Self {
            raw_data,
            sig: None,
        }
    }
}


/// Structure of the Notary.
pub struct Notary {
    pub kp: Keypair,
    pub version: ZkOraclesVersion,
}

impl Notary {
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        let kp = Keypair::rand(&mut rng);
        Self {
            kp,
            version: ZkOraclesVersion::VERSION0_1_0,
        }
    }

    /// Create a signed file.
    pub fn create_file(
        &self,
        signer: &mut impl Signer<NotaryFileRawData>,
        raw_data: &NotaryFileRawData,
    ) -> NotaryFile {
        let sig = signer.sign(&self.kp, raw_data);
        NotaryFile {
            raw_data: raw_data.clone(),
            sig: Some(sig),
        }
    }

    /// Verify the validity of a notarization file.
    pub fn verify_file(
        &self,
        signer: &mut impl Signer<NotaryFileRawData>,
        notary_file: &NotaryFile,
    ) -> bool {
        signer.verify(
            &notary_file.sig.as_ref().unwrap(),
            &self.kp.public,
            &notary_file.raw_data,
        )
    }
}

mod tests {
    #[test]
    fn notary_test() {
        use crate::{Notary, NotaryFileRawData, ZkOraclesVersion};
        use mina_curves::pasta::Fp;

        let client_key_share_commitment = Fp::from(0);
        let notary_key_share = [0u8; 16];
        let encrypted_query_length = 10u32;
        let encrypted_query = vec![0u8; 16];
        let encrypted_query_iv = [0u8; 12];
        let encrypted_response_length = 10u32;
        let encrypted_response = vec![0u8; 16];
        let encrypted_response_iv = [0u8; 12];
        let server_address = vec![0u8; 16];
        let time_stamp = 20221113u64;
        let validity_period = 1000u64;

        let notary = Notary::new();
        let raw_data = NotaryFileRawData::new(
            client_key_share_commitment,
            notary_key_share,
            encrypted_query_length,
            encrypted_query,
            encrypted_query_iv,
            encrypted_response_length,
            encrypted_response,
            encrypted_response_iv,
            server_address,
            time_stamp,
            validity_period,
        );
        let mut signer =
            mina_signer::create_kimchi::<NotaryFileRawData>(ZkOraclesVersion::VERSION0_1_0);

        let notary_file = notary.create_file(&mut signer, &raw_data);

        let res = notary.verify_file(&mut signer, &notary_file);

        assert_eq!(res, true);
    }
}
