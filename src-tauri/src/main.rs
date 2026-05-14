// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod kr_ibe;
mod kr_ibi;
mod kr_peks;
mod kr_paeks;

use kr_ibe::api::*;
use kr_ibi::api::*;
use kr_peks::api::*;
use kr_paeks::api::*;

mod system;

use system::{setup, user, upload, search, download, auth};

#[tauri::command]
fn setup_all(k: usize) {
    setup::setup_all(k);
}

#[tauri::command]
fn register(id: String) -> Result<String, String> {
    user::register_user(&id)
}

#[tauri::command]
fn upload_file(
    sender: String,
    receiver: String,
    msg: String,
    keyword: String,
    payload_type: String,
    file_name: Option<String>,
    mime_type: Option<String>,
    content_base64: Option<String>,
) -> Result<(), String> {
    upload::upload(
        &sender,
        &receiver,
        &msg,
        &keyword,
        &payload_type,
        file_name,
        mime_type,
        content_base64,
    )
}

#[tauri::command]
fn search_keyword(user: String, keyword: String) -> Result<Vec<usize>, String> {
    search::search(&user, &keyword)
}

#[tauri::command]
fn download_file(user: String, index: usize) -> Result<system::state::SharedPayload, String> {
    download::download(&user, index)
}

#[tauri::command]
fn login_start(id: String) -> Result<(String, String), String> {
    auth::login_start(&id)
}

#[tauri::command]
fn login_respond(id: String) -> Result<(String, String), String> {
    auth::login_respond(&id)
}

#[tauri::command]
fn login_verify(id: String, s1: String, s2: String) -> Result<bool, String> {
    auth::login_verify(&id, &s1, &s2)
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
             // KR-IBE
             kr_ibe_setup,
             kr_ibe_extract,
             kr_ibe_encrypt,
             kr_ibe_decrypt,
 
             // KR-IBI
             kr_ibi_setup,
             kr_ibi_extract,
             kr_ibi_sign,
             kr_ibi_verify,
 
             // KR-PEKS
             kr_peks_setup,
             kr_peks_keygen,
             kr_peks_encrypt,
             kr_peks_trapdoor,
             kr_peks_test,
 
             // KR-PAEKS
             kr_paeks_setup,
             kr_paeks_keygen,
             kr_paeks_encrypt,
             kr_paeks_trapdoor,
             kr_paeks_test,

             //system
            setup_all,
            register,
            upload_file,
            search_keyword,
            download_file,
            login_start,
            login_respond,
            login_verify
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri app");
}
