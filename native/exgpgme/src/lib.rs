#[macro_use] extern crate rustler;
#[macro_use] extern crate lazy_static;
extern crate gpgme;

use rustler::{Env, Term};
use rustler::schedule::SchedulerFlags;

#[macro_use] mod helpers;
#[macro_use] mod keys;
mod context;
mod results;
mod engine;
mod protocol;
mod encrypt_flags;
mod pinentry_mode;
mod sign_mode;
mod validity;
mod key_algorithm;
mod hash_algorithm;
mod notation;

rustler::init!(
    "Elixir.ExGpgme.Context",
    [from_protocol, protocol, armor?, set_armor, text_mode?, set_text_mode, offline?, set_offline, get_flag, set_flag, engine_info, set_engine_path, set_engine_home_dir, pinentry_mode, set_pinentry_mode, import, find_key, delete_key, delete_secret_key, decrypt, decrypt_with_flags, sign_and_encrypt_with_flags, sign_with_mode, verify_opaque],
    load = on_load
);

fn on_load<'a>(env: Env<'a>, _load_info: Term<'a>) -> bool {
    rustler::resource!(context::resource::ContextNifResource, env);
    rustler::resource!(keys::KeyResource, env);
    true
}
