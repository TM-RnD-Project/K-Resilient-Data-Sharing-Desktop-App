use crate::system::state::APP_STATE;

use crate::kr_ibe::main as kribe_core;
use crate::kr_ibi::main as kribi_core;
use crate::kr_paeks::main as krpaeks_core;

use crate::kr_ibe::params::Params as IbeParams;
use crate::kr_ibi::params::Params as IbiParams;
use crate::kr_paeks::params::Params as PaeksParams;

pub fn setup_all(k: usize) {
    let mut state = APP_STATE.lock().unwrap();

    let mut ibe_params = IbeParams::new();
    kribe_core::setup(&mut ibe_params, k);
    state.ibe_params = Some(ibe_params);

    let mut ibi_params = IbiParams::new();
    kribi_core::setup(&mut ibi_params, k);
    state.ibi_params = Some(ibi_params);

    let mut paeks_params = PaeksParams::new();
    krpaeks_core::setup(&mut paeks_params, k);
    state.paeks_params = Some(paeks_params);
}