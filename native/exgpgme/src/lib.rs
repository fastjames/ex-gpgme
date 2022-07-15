#[macro_use] extern crate rustler;
extern crate gpgme;

use rustler::{Env, Term};

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
    [
       context::from_protocol,
       context::get_protocol,
       context::armor,
       context::set_armor,
       context::text_mode,
       context::set_text_mode,
       context::offline,
       context::set_offline,
       context::get_flag,
       context::set_flag,
       context::engine_info,
       context::set_engine_path,
       context::set_engine_home_dir,
       context::get_pinentry_mode,
       context::set_pinentry_mode,
       context::import,
       context::find_key,
       context::delete_key,
       context::delete_secret_key,
       context::decrypt,
       context::encrypt_with_flags,
       context::sign_and_encrypt_with_flags,
       context::sign_with_mode,
       context::verify_opaque
    ],
    load = on_load
);

fn on_load<'a>(env: Env<'a>, _load_info: Term<'a>) -> bool {
    rustler::resource!(context::resource::ContextNifResource, env);
    rustler::resource!(keys::KeyResource, env);
    true
}
