use gpgme::engine::EngineInfo;
use rustler::{Term, Env, Encoder};
use rustler::types::elixir_struct;
use std::str::Utf8Error;
use protocol::XProtocol;

mod atoms {
    atoms! {
        protocol,
        path,
        home_dir,
        version,
        required_version
    }
}

fn get_engine_info<'a>(value: Result<&str, Option<Utf8Error>>, env: Env<'a>) -> Result<Term<'a>, Utf8Error> {
    match value {
        Ok(result) => Ok(String::from(result).encode(env)),
        Err(None) => Ok(String::new().encode(env)),
        Err(Some(error)) => Err(error)
    }
}

pub fn engine_info_to_term<'a>(engine_info: EngineInfo, env: Env<'a>) -> Result<Term<'a>, Utf8Error> {
    let protocol_atom = atoms::protocol().encode(env);
    let path_atom = atoms::path().encode(env);
    let home_dir_atom = atoms::home_dir().encode(env);
    let version_atom = atoms::version().encode(env);
    let required_version_atom = atoms::required_version().encode(env);

    Ok(
        elixir_struct::make_ex_struct(env, "Elixir.ExGpgme.Engine.EngineInfo").ok().unwrap()
            .map_put(protocol_atom, XProtocol(engine_info.protocol()).encode(env)).ok().unwrap()
            .map_put(path_atom, get_engine_info(engine_info.path(), env)?).ok().unwrap()
            .map_put(home_dir_atom, get_engine_info(engine_info.home_dir(), env)?).ok().unwrap()
            .map_put(version_atom, get_engine_info(engine_info.version(), env)?).ok().unwrap()
            .map_put(required_version_atom, get_engine_info(engine_info.required_version(), env)?).ok().unwrap()
    )
}
