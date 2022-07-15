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
    atoms! {
        ok,
        error,
        not_set
    }
}

#[rustler::nif]
pub fn from_protocol<'a>(env: Env<'a>, protocol_arg: Term) -> NifResult<Term<'a>> {
    let protocol = protocol::arg_to_protocol(protocol_arg)?;

    let context = try_gpgme!(Context::from_protocol(protocol), env);

    Ok((atoms::ok(), resource::wrap_context(context)).encode(env))
}

#[rustler::nif]
pub fn get_protocol<'a>(env: Env<'a>, context_arc: ResourceArc<resource::ContextNifResource>) -> NifResult<Term<'a>> {
    unpack_immutable_context!(context, context_arc);
    Ok(protocol::protocol_to_nif(env, context.protocol()))
}

#[rustler::nif]
pub fn offline<'a>(env: Env<'a>, context_arc: ResourceArc<resource::ContextNifResource>) -> NifResult<Term<'a>> {
    unpack_immutable_context!(context, context_arc);
    Ok(context.offline().encode(env))
}

#[rustler::nif]
pub fn set_offline<'a>(env: Env<'a>, context_arc: ResourceArc<resource::ContextNifResource>, yes: bool) -> NifResult<Term<'a>> {
    unpack_mutable_context!(context, context_arc);
    context.set_offline(yes);

    Ok(atoms::ok().encode(env))
}

#[rustler::nif]
pub fn text_mode<'a>(env: Env<'a>, context_arc: ResourceArc<resource::ContextNifResource>) -> NifResult<Term<'a>> {
    unpack_immutable_context!(context, context_arc);
    Ok(context.text_mode().encode(env))
}

#[rustler::nif]
pub fn set_text_mode<'a>(env: Env<'a>, context_arc: ResourceArc<resource::ContextNifResource>, yes: bool) -> NifResult<Term<'a>> {
    unpack_mutable_context!(context, context_arc);
    context.set_text_mode(yes);

    Ok(atoms::ok().encode(env))
}

#[rustler::nif]
pub fn armor<'a>(env: Env<'a>, context_arc: ResourceArc<resource::ContextNifResource>) -> NifResult<Term<'a>> {
    unpack_immutable_context!(context, context_arc);
    Ok(context.armor().encode(env))
}

#[rustler::nif]
pub fn set_armor<'a>(env: Env<'a>, context_arc: ResourceArc<resource::ContextNifResource>, yes: bool) -> NifResult<Term<'a>> {
    unpack_mutable_context!(context, context_arc);
    context.set_armor(yes);

    Ok(atoms::ok().encode(env))
}


#[rustler::nif]
pub fn get_flag<'a>(env: Env<'a>, context_arc: ResourceArc<resource::ContextNifResource>, name: String) -> NifResult<Term<'a>> {
    unpack_immutable_context!(context, context_arc);

    match context.get_flag(name) {
        Ok(result) => Ok((atoms::ok(), String::from(result)).encode(env)),
        Err(_) => Ok((atoms::error(), atoms::not_set()).encode(env))
    }
}

#[rustler::nif]
pub fn set_flag<'a>(env: Env<'a>, context_arc: ResourceArc<resource::ContextNifResource>, name: String, value: String) -> NifResult<Term<'a>> {
    unpack_mutable_context!(context, context_arc);

    try_gpgme!(context.set_flag(name, value), env);

    Ok(atoms::ok().encode(env))
}

#[rustler::nif]
pub fn engine_info<'a>(env: Env<'a>, context_arc: ResourceArc<resource::ContextNifResource>) -> NifResult<Term<'a>> {
    unpack_immutable_context!(context, context_arc);
    Ok(
        match engine::engine_info_to_term(context.engine_info(), env) {
            Ok(result) => (atoms::ok(), result).encode(env),
            Err(_) => (atoms::error(), String::from("Could not decode cyphertext to utf8")).encode(env)
        }
    )
}

#[rustler::nif]
pub fn set_engine_path<'a>(env: Env<'a>, context_arc: ResourceArc<resource::ContextNifResource>, path: String) -> NifResult<Term<'a>> {
    unpack_mutable_context!(context, context_arc);
    try_gpgme!(context.set_engine_path(path), env);

    Ok(atoms::ok().encode(env))
}


#[rustler::nif]
pub fn set_engine_home_dir<'a>(env: Env<'a>, context_arc: ResourceArc<resource::ContextNifResource>, home_dir: String) -> NifResult<Term<'a>> {
    unpack_mutable_context!(context, context_arc);
    try_gpgme!(context.set_engine_home_dir(home_dir), env);

    Ok(atoms::ok().encode(env))
}


#[rustler::nif]
pub fn get_pinentry_mode<'a>(env: Env<'a>, context_arc: ResourceArc<resource::ContextNifResource>) -> NifResult<Term<'a>> {
    unpack_immutable_context!(context, context_arc);
    Ok(pinentry_mode::pinentry_mode_to_term(context.pinentry_mode(), env))
}


#[rustler::nif]
pub fn set_pinentry_mode<'a>(env: Env<'a>, context_arc: ResourceArc<resource::ContextNifResource>, mode_arg: Term) -> NifResult<Term<'a>> {
    unpack_mutable_context!(context, context_arc);

    let mode = pinentry_mode::arg_to_pinentry_mode(mode_arg)?;

    try_gpgme!(context.set_pinentry_mode(mode), env);

    Ok(atoms::ok().encode(env))
}

#[rustler::nif(schedule = "DirtyIo")]
pub fn import<'a>(env: Env<'a>, context_arc: ResourceArc<resource::ContextNifResource>, data: String) -> NifResult<Term<'a>> {
    unpack_mutable_context!(context, context_arc);

    let result = try_gpgme!(context.import(data), env);

    Ok((atoms::ok(), transform_import_result(env, result)).encode(env))
}

#[rustler::nif(schedule = "DirtyIo")]
pub fn find_key<'a>(env: Env<'a>, context_arc: ResourceArc<resource::ContextNifResource>, fingerprint: String) -> NifResult<Term<'a>> {
    unpack_immutable_context!(context, context_arc);

    let result = try_gpgme!(context.find_key(fingerprint), env);

    Ok((atoms::ok(), keys::wrap_key(result)).encode(env))
}

#[rustler::nif(schedule = "DirtyIo")]
pub fn encrypt_with_flags<'a>(env: Env<'a>, context_arc: ResourceArc<resource::ContextNifResource>, key_list_arg: Term, data: String, flags_arg: Term) -> NifResult<Term<'a>> {
    unpack_mutable_context!(context, context_arc);
    unpack_key_list!(recipients, key_list_arg);

    keys::keys_not_empty(recipients.len())?;

    let flags: EncryptFlags = encrypt_flags::arg_to_protocol(flags_arg.decode::<ListIterator>()?)?;

    let mut cyphertext: Vec<u8> = Vec::new();
    try_gpgme!(context.encrypt_with_flags(recipients, data, &mut cyphertext, flags), env);

    decode_context_result!(cyphertext, env)
}

#[rustler::nif(schedule = "DirtyIo")]
pub fn sign_and_encrypt_with_flags<'a>(env: Env<'a>, context_arc: ResourceArc<resource::ContextNifResource>, key_list_arg: Term, data: String, flags_arg: Term) -> NifResult<Term<'a>> {
    unpack_mutable_context!(context, context_arc);
    unpack_key_list!(recipients, key_list_arg);

    keys::keys_not_empty(recipients.len())?;

    let flags: EncryptFlags = encrypt_flags::arg_to_protocol(flags_arg.decode::<ListIterator>()?)?;

    let mut cyphertext: Vec<u8> = Vec::new();
    try_gpgme!(context.sign_and_encrypt_with_flags(recipients, data, &mut cyphertext, flags), env);

    decode_context_result!(cyphertext, env)
}

#[rustler::nif(schedule = "DirtyIo")]
pub fn delete_key<'a>(env: Env<'a>, context_arc: ResourceArc<resource::ContextNifResource>, key_arc_arg: Term) -> NifResult<Term<'a>> {
    unpack_mutable_context!(context, context_arc);

    let key_arc = key_arc_arg.decode::<ResourceArc<keys::KeyResource>>()?;
    let key_ref = key_arc.deref();
    let key: &Key = &key_ref.key;

    try_gpgme!(context.delete_key(key), env);

    Ok(atoms::ok().encode(env))
}

#[rustler::nif(schedule = "DirtyIo")]
pub fn delete_secret_key<'a>(env: Env<'a>, context_arc: ResourceArc<resource::ContextNifResource>, key_arc_arg: Term) -> NifResult<Term<'a>> {
    unpack_mutable_context!(context, context_arc);

    let key_arc = key_arc_arg.decode::<ResourceArc<keys::KeyResource>>()?;
    let key_ref = key_arc.deref();
    let key: &Key = &key_ref.key;

    try_gpgme!(context.delete_secret_key(key), env);

    Ok(atoms::ok().encode(env))
}

#[rustler::nif(schedule = "DirtyIo")]
pub fn decrypt<'a>(env: Env<'a>, context_arc: ResourceArc<resource::ContextNifResource>, cyphertext: String) -> NifResult<Term<'a>> {
    unpack_mutable_context!(context, context_arc);

    let mut cleartext: Vec<u8> = Vec::new();

    try_gpgme!(context.decrypt(cyphertext, &mut cleartext), env);

    decode_context_result!(cleartext, env)
}

#[rustler::nif(schedule = "DirtyIo")]
pub fn sign_with_mode<'a>(env: Env<'a>, context_arc: ResourceArc<resource::ContextNifResource>, mode_arg: Term, data: String) -> NifResult<Term<'a>> {
    unpack_mutable_context!(context, context_arc);

    let mode = sign_mode::arg_to_sign_mode(mode_arg)?;

    let mut signature: Vec<u8> = Vec::new();

    try_gpgme!(context.sign(mode, data, &mut signature), env);

    decode_context_result!(signature, env)
}

#[rustler::nif(schedule = "DirtyIo")]
pub fn verify_opaque<'a>(env: Env<'a>, context_arc: ResourceArc<resource::ContextNifResource>, signature: String, data: String) -> NifResult<Term<'a>> {
    unpack_mutable_context!(context, context_arc);

    let result = try_gpgme!(context.verify_opaque(signature, data), env);

    match transform_verification_result(env, result) {
        Ok(nif_result) => Ok((atoms::ok(), nif_result).encode(env)),
        Err(_) => Ok((atoms::error(), String::from("Could not decode cyphertext to utf8")).encode(env))
    }
}
