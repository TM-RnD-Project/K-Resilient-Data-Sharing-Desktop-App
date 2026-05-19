use crate::system::state::APP_STATE;

use crate::kr_ibe::main as kribe_core;
use crate::kr_ibi::main as kribi_core;
use crate::kr_paeks::main as krpaeks_core;
use crate::kr_peks::main as krpeks_core;

use crate::kr_ibe::params::Params as IbeParams;
use crate::kr_ibi::params::Params as IbiParams;

use crate::kr_peks::{
    params::Params as PeksParams, private_key::PrivateKey as PeksPrivateKey,
    public_key::PublicKey as PeksPublicKey,
};

use crate::kr_paeks::params::Params as PaeksParams;

pub fn setup_all(k: usize) {
    let mut state = APP_STATE.lock().unwrap();

    // =========================
    // KR-IBE Setup
    // =========================
    let mut ibe_params = IbeParams::new();
    kribe_core::setup(&mut ibe_params, k);
    state.ibe_params = Some(ibe_params);

    // =========================
    // KR-IBI Setup
    // =========================
    let mut ibi_params = IbiParams::new();
    kribi_core::setup(&mut ibi_params, k);
    state.ibi_params = Some(ibi_params);

    // =========================
    // KR-PEKS Setup
    // =========================
    let mut peks_params = PeksParams::new();
    krpeks_core::setup(&mut peks_params, k);

    let mut peks_pk = PeksPublicKey::new();
    let mut peks_sk = PeksPrivateKey::new();

    krpeks_core::keygen(&peks_params, &mut peks_pk, &mut peks_sk);

    state.peks_params = Some(peks_params);
    state.peks_pk = Some(peks_pk);
    state.peks_sk = Some(peks_sk);

    // =========================
    // KR-PAEKS Setup
    // =========================
    let mut paeks_params = PaeksParams::new();
    krpaeks_core::setup(&mut paeks_params, k);

    state.paeks_params = Some(paeks_params);

    println!("System setup completed.");
}
