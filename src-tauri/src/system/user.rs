use crate::system::state::{PaeksKeyPair, APP_STATE};
use crate::system::utils::id_to_bytes;

use crate::kr_ibe::{main as kribe_core, private_key::PrivateKey as IbePrivateKey};

use crate::kr_paeks::{
    main as krpaeks_core, private_key::PrivateKey as PaeksPrivateKey,
    public_key::PublicKey as PaeksPublicKey,
};

pub fn register_user(id: &str) -> Result<String, String> {
    let mut state = APP_STATE.lock().map_err(|_| "State lock failed")?;

    if state.users.contains_key(id) {
        return Ok(format!("User {} already registered.", id));
    }

    let ibe_params = state
        .ibe_params
        .as_ref()
        .ok_or("IBE params not initialised. Call setup_all() first.")?;

    let paeks_params = state
        .paeks_params
        .as_ref()
        .ok_or("PAEKS params not initialised. Call setup_all() first.")?;

    let mut ibe_sk = IbePrivateKey::new();
    let id_bytes = id_to_bytes(id);

    kribe_core::extract(ibe_params, &mut ibe_sk, &id_bytes);

    let mut paeks_pk = PaeksPublicKey::new();
    let mut paeks_sk = PaeksPrivateKey::new();

    krpaeks_core::keygen(paeks_params, &mut paeks_pk, &mut paeks_sk);

    state.users.insert(id.to_string(), ibe_sk);
    state.paeks_users.insert(
        id.to_string(),
        PaeksKeyPair {
            pk: paeks_pk,
            sk: paeks_sk,
        },
    );

    println!("Register called for ID: {}", id);

    Ok(format!("User {} registered successfully.", id))
}
