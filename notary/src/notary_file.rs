//! Define the notary file format

use mina_curves::pasta::Fp;
use mina_hasher::{Hashable, ROInput};
use mina_signer::{signature::Signature, Keypair, Signer};

use crate::ZkOraclesVersion;

/// Row data of a notarization file.
#[derive(Clone)]
pub struct NotaryFileRawData {
    /// Commitment of client write key share using Poseidon-based commitment.
    pub client_write_key_share_commitment: Fp,

    /// client write key share in notary.
    pub client_write_key_notary_share: [u8; 16],

    /// Commitment of server write key share using Poseidon-based commitment.
    pub server_write_key_share_commitment: Fp,

    /// server write key share in notary.
    pub server_write_key_notary_share: [u8; 16],

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
        client_write_key_share_commitment: Fp,
        client_write_key_notary_share: [u8; 16],
        server_write_key_share_commitment: Fp,
        server_write_key_notary_share: [u8; 16],
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
            client_write_key_share_commitment,
            client_write_key_notary_share,
            server_write_key_share_commitment,
            server_write_key_notary_share,
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
            .append_field(self.client_write_key_share_commitment)
            .append_bytes(self.client_write_key_notary_share.as_slice())
            .append_field(self.server_write_key_share_commitment)
            .append_bytes(self.server_write_key_notary_share.as_slice())
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
    use mina_hasher::Fp;
    use serde::{Deserialize, Serialize};
    #[derive(Serialize, Deserialize)]
    pub struct Query {
        ///Api-Key, the secret value that used to access the endpoint. (The api-key here is fake for test)
        api_key: String,

        ///Api-Timestamp
        pub api_timestamp: u64,

        /// SHA512 of " ", it is a fixed value here.
        pub api_content_hash: String,

        /// It is the output of HMAC-SHA512(apiSecret,preSign), where apiSecret is some secret value.
        /// preSign is the concatenation of the following items.
        /// 1. api-timestamp,
        /// 2. URL (e.g., https://api.bittrex.com/v3/balances/BCH),
        /// 3. HTTP method of the request (e.g., GET, POST,DELETE,etc.),
        /// 4. api-content_hash,
        /// 5. content of api_subaccount_id. It is empty here.
        pub api_signature: String,
    }

    #[derive(Serialize, Deserialize)]
    pub struct Response {
        /// The currency symbol, (e.g., BTC, ETH).
        pub currency_symbol: String,

        /// The total balance of the currency.
        total: f32,

        /// The available balance of the currency.
        available: f32,

        /// The updated time.
        pub updated_at: String,
    }

    #[derive(Debug)]
    struct Witness {
        /// the share of client write key.
        _client_write_key_share: [u8; 16],

        /// the randomness to commit the share of client write key.
        _client_write_key_share_randomness: Fp,

        /// the share of server write key.
        _server_write_key_share: [u8; 16],

        /// the randomness to commit the share of client wirte key.
        _server_write_key_share_randomness: Fp,

        /// the api key
        _api_key: String,

        /// the api secret
        _api_secret: String,

        /// the total amount of the currency.
        _currency_total: f32,

        /// the available amount of the currency.
        _currency_available: f32,
    }

    #[test]
    fn notary_test() {
        use crate::{poseidon_commitment, PInput};
        use crate::{Notary, NotaryFileRawData, ZkOraclesVersion};
        use aes_gcm::{
            aead::{
                generic_array::{typenum::U16, GenericArray},
                Aead, OsRng,
            },
            Aes128Gcm, KeyInit, Nonce,
        };
        use crypto_core::AesRng;
        use mina_curves::pasta::Fp;
        use mina_hasher::create_kimchi;
        use o1_utils::FieldHelpers;
        use rand_core::RngCore;

        // Initiate the query
        let query_json = Query{
            // This api_key is fake for the test.
            api_key: "aec6723af4513c0430cc0a28425774de".to_string(),
            // timestamp
            api_timestamp: 1669536401556u64,
            // This is the output of SHA512(""), which is public and fixed.
            api_content_hash: "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e".to_string(),

            // The apiSecret = "1041f46c61f053cc33eb781fb7a4c758", which is fake.
            // The api_signature = HMAC-SHA512(apiSecret, preSign),
            // preSign is concatenated by the above items. Details are described in https://bittrex.github.io/api/v3
            // api_timestamp = 1669536401556,
            // URL = https://api.bittrex.com/v3/balances/BCH,
            // HTTP method: GET,
            // api_content_hash = cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e,
            // apiSubAccountID = "",
            api_signature: "fa124df9e3164d8d90c0f5f3213d8c39a6a0ef14f88db8b38201eedb91f66fd343289e593134feeec061ec000371d65f53d6a4b727196ed664a8bde71167c1b9".to_string(),
        };

        let query = serde_json::to_vec(&query_json).unwrap();

        // The iv used to encrypt query in AES-GCM
        let iv_query = [0u8; 12];

        // Initiate the response
        let response_json = Response {
            currency_symbol: "BCH".to_string(),
            total: 1.5,
            available: 1.5,
            updated_at: "2001-01-01T00:00:00Z".to_string(),
        };

        let response = serde_json::to_vec(&response_json).unwrap();

        // The iv used to encrypt response in AES-GCM
        let iv_response = [1u8; 12];

        // generate random share of client_write_key,
        // client_wirte_key = client_write_key_share xor client_write_key_notary_share,
        // the client_write_key_share is given to the client,
        // the client_write_key_notary_share is given to the notary.
        let client_write_key_share = Aes128Gcm::generate_key(&mut OsRng);
        let client_write_key_notary_share = Aes128Gcm::generate_key(&mut OsRng);
        let client_write_key_share: [u8; 16] = client_write_key_share.into();
        let client_write_key_notary_share: [u8; 16] = client_write_key_notary_share.into();

        let client_write_key: Vec<u8> = client_write_key_share
            .iter()
            .zip(client_write_key_notary_share)
            .map(|(x, y)| x ^ y)
            .collect();

        let client_write_key_enc: GenericArray<u8, U16> =
            GenericArray::clone_from_slice(&client_write_key[0..16]);

        // encrypt the query with client_write_key under AES128-GCM with nonce iv_query.
        let nonce_query = Nonce::from(iv_query);
        let encrypted_query = Aes128Gcm::new(&client_write_key_enc);
        let encrypted_query = encrypted_query
            .encrypt(&nonce_query, query.as_slice().as_ref())
            .unwrap();

        // generate random share of server_write_key,
        // server_wirte_key = server_write_key_share xor server_write_key_notary_share,
        // the server_write_key_share is given to the client,
        // the server_write_key_notary_share is given to the notary.
        let server_write_key_share = Aes128Gcm::generate_key(&mut OsRng);
        let server_write_key_notary_share = Aes128Gcm::generate_key(&mut OsRng);
        let server_write_key_share: [u8; 16] = server_write_key_share.into();
        let server_write_key_notary_share: [u8; 16] = server_write_key_notary_share.into();
        let server_write_key: Vec<u8> = server_write_key_share
            .iter()
            .zip(server_write_key_notary_share)
            .map(|(x, y)| x ^ y)
            .collect();

        let server_write_key_enc: GenericArray<u8, U16> =
            GenericArray::clone_from_slice(&server_write_key[0..16]);

        // encrypt the response with server_write_key under AES128-GCM with nonce iv_response.
        let nonce_response = Nonce::from(iv_response);
        let encrypted_response = Aes128Gcm::new(&server_write_key_enc);
        let encrypted_response = encrypted_response
            .encrypt(&nonce_response, response.as_slice().as_ref())
            .unwrap();

        // generate client_write_key_share_randomness.
        let mut rng = AesRng::new();
        let mut rand_bytes = [0u8; 32];
        rng.fill_bytes(&mut rand_bytes);
        let client_write_key_share_randomness = Fp::from_bytes(&rand_bytes).unwrap();

        // generate client_write_key_share_commitment using poseidon-based commitment.
        let mut hasher = create_kimchi::<PInput>(0);
        let client_write_key_share_commitment = poseidon_commitment(
            &mut hasher,
            client_write_key_share,
            client_write_key_share_randomness,
        );

        // generate server_write_key_share_randomness.
        let mut rng = AesRng::new();
        let mut rand_bytes = [0u8; 32];
        rng.fill_bytes(&mut rand_bytes);
        let server_write_key_share_randomness = Fp::from_bytes(&rand_bytes).unwrap();

        // generate server_write_key_share_commitment using poseidon-based commitment.
        let server_write_key_share_commitment = poseidon_commitment(
            &mut hasher,
            server_write_key_share,
            server_write_key_share_randomness,
        );

        let client_write_key_share_commitment = client_write_key_share_commitment;
        let client_write_key_notary_share = client_write_key_notary_share;
        let server_write_key_share_commitment = server_write_key_share_commitment;
        let server_write_key_notary_share = server_write_key_notary_share;
        let encrypted_query_length = encrypted_query.len() as u32;
        let encrypted_query = encrypted_query;
        let encrypted_query_iv = iv_query;
        let encrypted_response_length = encrypted_response.len() as u32;
        let encrypted_response = encrypted_response;
        let encrypted_response_iv = iv_response;
        let server_address = b"https://api.bittrex.com/v3/balances/BCH".to_vec();
        let time_stamp = query_json.api_timestamp;
        let validity_period = 1000u64;

        let notary = Notary::new();
        let raw_data = NotaryFileRawData::new(
            client_write_key_share_commitment,
            client_write_key_notary_share,
            server_write_key_share_commitment,
            server_write_key_notary_share,
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

        // generate witness
        let _witness = Witness {
            _client_write_key_share: client_write_key_share,
            _client_write_key_share_randomness: client_write_key_share_randomness,
            _server_write_key_share: server_write_key_share,
            _server_write_key_share_randomness: server_write_key_share_randomness,
            _api_key: query_json.api_key,
            _api_secret: "1041f46c61f053cc33eb781fb7a4c758".to_string(),
            _currency_total: response_json.total,
            _currency_available: response_json.available,
        };

        //println!("{:?}", witness);

        let mut signer =
            mina_signer::create_kimchi::<NotaryFileRawData>(ZkOraclesVersion::VERSION0_1_0);

        let notary_file = notary.create_file(&mut signer, &raw_data);

        let res = notary.verify_file(&mut signer, &notary_file);

        assert_eq!(res, true);

        // The proof system should prove the following statement.
        // The public 
    }
}
