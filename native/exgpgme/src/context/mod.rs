use rustler::{Env, Term, NifResult, Encoder};
use rustler::resource::ResourceArc;
use rustler::types::list::ListIterator;
use gpgme::{Context, EncryptFlags};
use gpgme::keys::Key;
use std::ops::Deref;
use results::verification_result::transform_verification_result;
use keys;
use protocol;
use encrypt_flags;
use engine;
use pinentry_mode;
use sign_mode;
use results::import_result::transform_import_result;

#[macro_use] pub mod helpers;
#[macro_use] pub mod resource;

mod atoms {
    rustler::atoms! {
        ok,
        error,
        not_set,
    }
}

// ok, so we need to convert args to the actual args
// it worked! Now to replicate it

#[rustler::nif]
pub fn from_protocol<'a>(env: Env<'a>, protocolStr: Term) -> NifResult<Term<'a>> {
    let protocol = protocol::arg_to_protocol(protocolStr)?;

    let context = try_gpgme!(Context::from_protocol(protocol), env);

    Ok((atoms::ok(), resource::wrap_context(context)).encode(env))
}

context_getter!(protocol, context, env, protocol::protocol_to_nif(env, context.protocol()));
context_getter!(offline, context, env, context.offline().encode(env));
context_setter!(set_offline, context, env, yes, bool, { context.set_offline(yes) });
context_getter!(text_mode, context, env, context.text_mode().encode(env));
context_setter!(set_text_mode, context, env, yes, bool, { context.set_text_mode(yes) });
context_getter!(armor, context, env, context.armor().encode(env));
context_setter!(set_armor, context, env, yes, bool, { context.set_armor(yes) });

#[rustler::nif]
pub fn get_flag<'a>(env: Env<'a>, contextArgs: Term, name: String) -> NifResult<Term<'a>> {
    unpack_immutable_context!(context, contextArgs);

    match context.get_flag(name) {
        Ok(result) => Ok((atoms::ok(), String::from(result)).encode(env)),
        Err(_) => Ok((atoms::error(), atoms::not_set()).encode(env))
    }
}

#[rustler::nif]
pub fn set_flag<'a>(env: Env<'a>, contextArgs: Term, name: String, value: String) -> NifResult<Term<'a>> {
    unpack_mutable_context!(context, contextArgs);

    try_gpgme!(context.set_flag(name, value), env);

    Ok(atoms::ok().encode(env))
}

context_getter!(engine_info, context, env, {
    match engine::engine_info_to_term(context.engine_info(), env) {
        Ok(result) => (atoms::ok(), result).encode(env),
        Err(_) => (atoms::error(), String::from("Could not decode cyphertext to utf8")).encode(env)
    }
});

context_setter!(set_engine_path, context, env, path, String, { try_gpgme!(context.set_engine_path(path), env) });
context_setter!(set_engine_home_dir, context, env, home_dir, String, { try_gpgme!(context.set_engine_home_dir(home_dir), env) });

context_getter!(pinentry_mode, context, env, pinentry_mode::pinentry_mode_to_term(context.pinentry_mode(), env));

// pub fn set_pinentry_mode<'a>(env: Env<'a>, args: &[Term<'a>]) -> NifResult<Term<'a>> {
#[rustler::nif]
pub fn set_pinentry_mode<'a>(env: Env<'a>, contextArgs: Term, pinentryModeArg: Term) -> NifResult<Term<'a>> {
    unpack_mutable_context!(context, contextArgs);

    let mode = pinentry_mode::arg_to_pinentry_mode(pinentryModeArg)?;

    try_gpgme!(context.set_pinentry_mode(mode), env);

    Ok(atoms::ok().encode(env))
}

#[rustler::nif(
    schedule="DirtyIo"
)]
pub fn import<'a>(env: Env<'a>, contextArg: Term, data: String) -> NifResult<Term<'a>> {
    unpack_mutable_context!(context, contextArg);

    let result = try_gpgme!(context.import(data), env);

    Ok((atoms::ok(), transform_import_result(env, result)).encode(env))
}

#[rustler::nif(
    schedule="DirtyIo"
)]
pub fn find_key<'a>(env: Env<'a>, contextArg: Term, fingerprint: String) -> NifResult<Term<'a>> {
    unpack_immutable_context!(context, contextArg);
    let result = try_gpgme!(context.get_key(fingerprint), env);

    Ok((atoms::ok(), keys::wrap_key(result)).encode(env))
}

#[rustler::nif(
    schedule="DirtyIo"
)]
pub fn encrypt_with_flags<'a>(env: Env<'a>, contextArg: Term, keyList: Term, data: String, flagsArg: Term) -> NifResult<Term<'a>> {
    unpack_mutable_context!(context, contextArg);
    unpack_key_list!(recipients, keyList);

    keys::keys_not_empty(recipients.len())?;

    let flags: EncryptFlags = encrypt_flags::arg_to_protocol(flagsArg.decode::<ListIterator>()?)?;

    let mut cyphertext: Vec<u8> = Vec::new();
    try_gpgme!(context.encrypt_with_flags(recipients, data, &mut cyphertext, flags), env);

    decode_context_result!(cyphertext, env)
}

#[rustler::nif]
pub fn sign_and_encrypt_with_flags<'a>(env: Env<'a>, contextArg: Term, keyList: Term, data: String, flagsArg: Term ) -> NifResult<Term<'a>> {
    unpack_mutable_context!(context, contextArg);
    unpack_key_list!(recipients, keyList);

    keys::keys_not_empty(recipients.len())?;

    let flags: EncryptFlags = encrypt_flags::arg_to_protocol(flagsArg.decode::<ListIterator>()?)?;

    let mut cyphertext: Vec<u8> = Vec::new();
    try_gpgme!(context.sign_and_encrypt_with_flags(recipients, data, &mut cyphertext, flags), env);

    decode_context_result!(cyphertext, env)
}

#[rustler::nif(
    schedule="DirtyIo"
)]
pub fn delete_key<'a>(env: Env<'a>, contextArg: Term, keyArcArg: Term) -> NifResult<Term<'a>> {
    unpack_mutable_context!(context, contextArg);

    let keyArc = keyArcArg.decode::<ResourceArc<keys::KeyResource>>()?;
    let key_ref = keyArc.deref();
    let key: &Key = &key_ref.key;

    try_gpgme!(context.delete_key(key), env);

    Ok(atoms::ok().encode(env))
}

#[rustler::nif(
    schedule="DirtyIo"
)]
pub fn delete_secret_key<'a>(env: Env<'a>, contextArg: Term, keyArcArg: Term) -> NifResult<Term<'a>> {
    unpack_mutable_context!(context, contextArg);

    let keyArc = keyArcArg.decode::<ResourceArc<keys::KeyResource>>()?;
    let key_ref = keyArc.deref();
    let key: &Key = &key_ref.key;

    try_gpgme!(context.delete_secret_key(key), env);

    Ok(atoms::ok().encode(env))
}

#[rustler::nif(
    schedule="DirtyIo"
)]
pub fn decrypt<'a>(env: Env<'a>, contextArg: Term, cyphertext: String) -> NifResult<Term<'a>> {
    unpack_mutable_context!(context, contextArg);

    // let cyphertext: String = args[1].decode::<String>()?;//.into_bytes();

    let mut cleartext: Vec<u8> = Vec::new();

    try_gpgme!(context.decrypt(cyphertext, &mut cleartext), env);

    decode_context_result!(cleartext, env)
}

#[rustler::nif]
pub fn sign_with_mode<'a>(env: Env<'a>, contextArg: Term, modeArg: Term, data: String) -> NifResult<Term<'a>> {
    unpack_mutable_context!(context, contextArg);

    let mode = sign_mode::arg_to_sign_mode(modeArg)?;

    let mut signature: Vec<u8> = Vec::new();

    try_gpgme!(context.sign(mode, data, &mut signature), env);

    decode_context_result!(signature, env)
}

#[rustler::nif]
pub fn verify_opaque<'a>(env: Env<'a>, contextArg: Term, signature: String, data: String) -> NifResult<Term<'a>> {
    unpack_mutable_context!(context, contextArg);

    let result = try_gpgme!(context.verify_opaque(signature, data), env);

    match transform_verification_result(env, result) {
        Ok(nif_result) => Ok((atoms::ok(), nif_result).encode(env)),
        Err(_) => Ok((atoms::error(), String::from("Could not decode cyphertext to utf8")).encode(env))
    }
}
