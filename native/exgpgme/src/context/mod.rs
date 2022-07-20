use rustler::{Atom, Encoder, Env, Error, NifResult, Term};
use rustler::resource::ResourceArc;
use rustler::types::list::ListIterator;
use gpgme::{Context, EncryptFlags};
use gpgme::keys::Key;
use std::ops::Deref;
use results::verification_result::transform_verification_result;
use keys;
use protocol;
use protocol::XProtocol;
use encrypt_flags;
use engine;
use pinentry_mode;
use pinentry_mode::XPinentryMode;
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

#[derive(NifTuple)]
pub struct FromProtocolResponse {
    ok: Atom,
    context: ResourceArc<resource::ContextNifResource>,
}

#[rustler::nif]
pub fn from_protocol(protocol_arg: Term) -> NifResult<FromProtocolResponse> {
    eprintln!("from_protocol: start");
    let protocol = protocol::arg_to_protocol(protocol_arg)?;
    eprintln!("from_protocol: after arg transform");

    // let context = try_gpgme!(Context::from_protocol(protocol));
    let result = Context::from_protocol(protocol);
    eprintln!("from_protocol: after from_protocol callout");

    let context = match result {
        Ok(context) => context,
        Err(err) => return Err(rustler::Error::Term(Box::new(err.description().into_owned())))
    };

    eprintln!("from_protocol: after try_gpgme");

    Ok(FromProtocolResponse {
        ok: atoms::ok(),
        context: resource::wrap_context(context)
    })
}

#[rustler::nif]
pub fn get_protocol(context_arc: ResourceArc<resource::ContextNifResource>) -> NifResult<XProtocol> {
    unpack_immutable_context!(context, context_arc);
    Ok(XProtocol(context.protocol()))
}

#[rustler::nif]
pub fn offline(context_arc: ResourceArc<resource::ContextNifResource>) -> bool {
    unpack_immutable_context!(context, context_arc);
    context.offline()
}

#[rustler::nif]
pub fn set_offline(context_arc: ResourceArc<resource::ContextNifResource>, yes: bool) -> Atom {
    unpack_mutable_context!(context, context_arc);
    context.set_offline(yes);

    atoms::ok()
}

#[rustler::nif]
pub fn text_mode(context_arc: ResourceArc<resource::ContextNifResource>) -> bool {
    unpack_immutable_context!(context, context_arc);
    context.text_mode()
}

#[rustler::nif]
pub fn set_text_mode(context_arc: ResourceArc<resource::ContextNifResource>, yes: bool) -> Atom {
    unpack_mutable_context!(context, context_arc);
    context.set_text_mode(yes);

    atoms::ok()
}

#[rustler::nif]
pub fn armor(context_arc: ResourceArc<resource::ContextNifResource>) -> bool {
    unpack_immutable_context!(context, context_arc);
    context.armor()
}

#[rustler::nif]
pub fn set_armor(context_arc: ResourceArc<resource::ContextNifResource>, yes: bool) -> Atom {
    unpack_mutable_context!(context, context_arc);
    context.set_armor(yes);

    atoms::ok()
}

#[derive(NifTuple)]
pub struct GetFlagResponse {
    ok: Atom,
    flag: String,
}

#[rustler::nif]
pub fn get_flag(context_arc: ResourceArc<resource::ContextNifResource>, name: String) -> NifResult<GetFlagResponse> {
    unpack_immutable_context!(context, context_arc);

    match context.get_flag(name) {
        Ok(result) => Ok(GetFlagResponse {
            ok: atoms::ok(),
            flag: String::from(result)
        }),
        Err(_) => Err(Error::Term(Box::new(atoms::not_set())))
    }
}

#[rustler::nif]
pub fn set_flag(context_arc: ResourceArc<resource::ContextNifResource>, name: String, value: String) -> NifResult<Atom> {
    unpack_mutable_context!(context, context_arc);

    try_gpgme!(context.set_flag(name, value));

    Ok(atoms::ok())
}

#[rustler::nif]
pub fn engine_info(env: Env, context_arc: ResourceArc<resource::ContextNifResource>) -> NifResult<Term> {
    unpack_immutable_context!(context, context_arc);
    Ok(
        match engine::engine_info_to_term(context.engine_info(), env) {
            Ok(result) => (atoms::ok(), result).encode(env),
            Err(_) => (atoms::error(), String::from("Could not decode cyphertext to utf8")).encode(env)
        }
    )
}

#[rustler::nif]
pub fn set_engine_path(context_arc: ResourceArc<resource::ContextNifResource>, path: String) -> NifResult<Atom> {
    unpack_mutable_context!(context, context_arc);
    try_gpgme!(context.set_engine_path(path));

    Ok(atoms::ok())
}


#[rustler::nif]
pub fn set_engine_home_dir(context_arc: ResourceArc<resource::ContextNifResource>, home_dir: String) -> NifResult<Atom> {
    unpack_mutable_context!(context, context_arc);
    try_gpgme!(context.set_engine_home_dir(home_dir));

    Ok(atoms::ok())
}


#[rustler::nif]
pub fn get_pinentry_mode(context_arc: ResourceArc<resource::ContextNifResource>) -> NifResult<XPinentryMode> {
    unpack_immutable_context!(context, context_arc);
    Ok(XPinentryMode(context.pinentry_mode()))
}


#[rustler::nif]
pub fn set_pinentry_mode(context_arc: ResourceArc<resource::ContextNifResource>, mode_arg: Term) -> NifResult<Atom> {
    unpack_mutable_context!(context, context_arc);

    let mode = pinentry_mode::arg_to_pinentry_mode(mode_arg)?;

    try_gpgme!(context.set_pinentry_mode(mode));

    Ok(atoms::ok())
}

#[rustler::nif(schedule = "DirtyIo")]
pub fn import(env: Env, context_arc: ResourceArc<resource::ContextNifResource>, data: String) -> NifResult<Term> {
    unpack_mutable_context!(context, context_arc);

    let result = try_gpgme!(context.import(data));

    Ok((atoms::ok(), transform_import_result(env, result)).encode(env))
}

#[rustler::nif(schedule = "DirtyIo")]
pub fn find_key(env: Env, context_arc: ResourceArc<resource::ContextNifResource>, fingerprint: String) -> NifResult<Term> {
    unpack_mutable_context!(context, context_arc);

    let result = try_gpgme!(context.get_key(fingerprint));

    Ok((atoms::ok(), keys::wrap_key(result)).encode(env))
}

#[rustler::nif(schedule = "DirtyIo")]
pub fn encrypt_with_flags<'a>(env: Env<'a>, context_arc: ResourceArc<resource::ContextNifResource>, key_list_arg: Term, data: String, flags_arg: Term) -> NifResult<Term<'a>> {
    unpack_mutable_context!(context, context_arc);
    unpack_key_list!(recipients, key_list_arg);

    keys::keys_not_empty(recipients.len())?;

    let flags: EncryptFlags = encrypt_flags::arg_to_protocol(flags_arg.decode::<ListIterator>()?)?;

    let mut cyphertext: Vec<u8> = Vec::new();
    try_gpgme!(context.encrypt_with_flags(recipients, data, &mut cyphertext, flags));

    decode_context_result!(cyphertext, env)
}

#[rustler::nif(schedule = "DirtyIo")]
pub fn sign_and_encrypt_with_flags<'a>(env: Env<'a>, context_arc: ResourceArc<resource::ContextNifResource>, key_list_arg: Term, data: String, flags_arg: Term) -> NifResult<Term<'a>> {
    unpack_mutable_context!(context, context_arc);
    unpack_key_list!(recipients, key_list_arg);

    keys::keys_not_empty(recipients.len())?;

    let flags: EncryptFlags = encrypt_flags::arg_to_protocol(flags_arg.decode::<ListIterator>()?)?;

    let mut cyphertext: Vec<u8> = Vec::new();
    try_gpgme!(context.sign_and_encrypt_with_flags(recipients, data, &mut cyphertext, flags));

    decode_context_result!(cyphertext, env)
}

#[rustler::nif(schedule = "DirtyIo")]
pub fn delete_key(context_arc: ResourceArc<resource::ContextNifResource>, key_arc_arg: Term) -> NifResult<Atom> {
    unpack_mutable_context!(context, context_arc);

    let key_arc = key_arc_arg.decode::<ResourceArc<keys::KeyResource>>()?;
    let key_ref = key_arc.deref();
    let key: &Key = &key_ref.key;

    try_gpgme!(context.delete_key(key));

    Ok(atoms::ok())
}

#[rustler::nif(schedule = "DirtyIo")]
pub fn delete_secret_key(context_arc: ResourceArc<resource::ContextNifResource>, key_arc_arg: Term) -> NifResult<Atom> {
    unpack_mutable_context!(context, context_arc);

    let key_arc = key_arc_arg.decode::<ResourceArc<keys::KeyResource>>()?;
    let key_ref = key_arc.deref();
    let key: &Key = &key_ref.key;

    try_gpgme!(context.delete_secret_key(key));

    Ok(atoms::ok())
}

#[rustler::nif(schedule = "DirtyIo")]
pub fn decrypt(env: Env, context_arc: ResourceArc<resource::ContextNifResource>, cyphertext: String) -> NifResult<Term> {
    unpack_mutable_context!(context, context_arc);

    let mut cleartext: Vec<u8> = Vec::new();

    try_gpgme!(context.decrypt(cyphertext, &mut cleartext));

    decode_context_result!(cleartext, env)
}

#[rustler::nif(schedule = "DirtyIo")]
pub fn sign_with_mode<'a>(env: Env<'a>, context_arc: ResourceArc<resource::ContextNifResource>, mode_arg: Term, data: String) -> NifResult<Term<'a>> {
    unpack_mutable_context!(context, context_arc);

    let mode = sign_mode::arg_to_sign_mode(mode_arg)?;

    let mut signature: Vec<u8> = Vec::new();

    try_gpgme!(context.sign(mode, data, &mut signature));

    decode_context_result!(signature, env)
}

#[rustler::nif(schedule = "DirtyIo")]
pub fn verify_opaque(env: Env, context_arc: ResourceArc<resource::ContextNifResource>, signature: String, data: String) -> NifResult<Term> {
    unpack_mutable_context!(context, context_arc);

    let result = try_gpgme!(context.verify_opaque(signature, data));

    match transform_verification_result(env, result) {
        Ok(nif_result) => Ok((atoms::ok(), nif_result).encode(env)),
        Err(_) => Ok((atoms::error(), String::from("Could not decode cyphertext to utf8")).encode(env))
    }
}
