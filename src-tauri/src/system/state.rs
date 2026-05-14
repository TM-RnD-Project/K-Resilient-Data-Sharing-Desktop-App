use std::collections::HashMap;
use std::sync::Mutex;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};

use mcore::ed25519::big;
use mcore::ed25519::ecp;

use crate::kr_ibe::{
    params::Params as IbeParams,
    private_key::PrivateKey as IbePrivateKey,
    ciphertext::Ciphertext as IbeCiphertext,
};

use crate::kr_ibi::params::Params as IbiParams;

use crate::kr_peks::{
    params::Params as PeksParams,
    public_key::PublicKey as PeksPublicKey,
    private_key::PrivateKey as PeksPrivateKey,
    ciphertext::Ciphertext as PeksCiphertext,
};

use crate::kr_paeks::{
    params::Params as PaeksParams,
    public_key::PublicKey as PaeksPublicKey,
    private_key::PrivateKey as PaeksPrivateKey,
    ciphertext::Ciphertext as PaeksCiphertext,
};

pub struct LoginSession {
    pub g_r: (ecp::ECP, ecp::ECP),
    pub c1: big::BIG,
    pub c2: big::BIG,
    pub r: (big::BIG, big::BIG),
}

#[derive(Clone)]
pub struct PaeksKeyPair {
    pub pk: PaeksPublicKey,
    pub sk: PaeksPrivateKey,
}

#[derive(Clone)]
pub enum SearchScheme {
    Peks,
    Paeks,
}

#[derive(Clone)]
pub enum SearchIndex {
    Peks(PeksCiphertext),
    Paeks(PaeksCiphertext),
}

#[derive(Clone)]
pub struct StoredData {
    pub ct: IbeCiphertext,
    pub search_index: SearchIndex,
    pub search_scheme: SearchScheme,
    pub sender: String,
    pub owner: String,
    pub keyword_hash: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SharedPayload {
    pub payload_type: String,
    pub content: String,
    pub file_name: Option<String>,
    pub mime_type: Option<String>,
    pub content_base64: Option<String>,
}

pub struct AppState {
    pub ibe_params: Option<IbeParams>,
    pub ibi_params: Option<IbiParams>,

    // KR-PEKS
    pub peks_params: Option<PeksParams>,
    pub peks_pk: Option<PeksPublicKey>,
    pub peks_sk: Option<PeksPrivateKey>,

    // KR-PAEKS
    pub paeks_params: Option<PaeksParams>,
    pub paeks_users: HashMap<String, PaeksKeyPair>,

    // KR-IBE user private keys
    pub users: HashMap<String, IbePrivateKey>,

    pub database: Vec<StoredData>,

    pub login_sessions: HashMap<String, LoginSession>,
    pub active_sessions: HashMap<String, bool>,
}

pub static APP_STATE: Lazy<Mutex<AppState>> = Lazy::new(|| {
    Mutex::new(AppState {
        ibe_params: None,
        ibi_params: None,

        peks_params: None,
        peks_pk: None,
        peks_sk: None,

        paeks_params: None,
        paeks_users: HashMap::new(),

        users: HashMap::new(),

        database: Vec::new(),

        login_sessions: HashMap::new(),
        active_sessions: HashMap::new(),
    })
});