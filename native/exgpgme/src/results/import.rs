use rustler::{Env, Term, Encoder};
use gpgme::results::Import;
use rustler::types::elixir_struct;

mod atoms {
    rustler_atoms! {
        atom fingerprint;
    }
}

pub fn transform_import<'a>(env: Env<'a>, import: Import) -> Term<'a> {
    let fingerprint_atom = atoms::fingerprint().encode(env);

    let fingerprint = import.fingerprint().expect("must be a string");

    elixir_struct::make_ex_struct(env, "Elixir.ExGpgme.Results.Import").ok().unwrap()
        .map_put(fingerprint_atom, String::from(fingerprint).encode(env)).ok().unwrap()
}
