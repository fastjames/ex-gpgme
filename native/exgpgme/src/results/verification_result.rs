use rustler::{Env, Term, Encoder};
use gpgme::results::VerificationResult;
use rustler::types::elixir_struct;
use std::str::Utf8Error;

use ::results::signature::transform_signature;

mod atoms {
    atoms! {
        filename,
        signatures
    }
}

pub fn transform_verification_result(env: Env, verification_result: VerificationResult) -> Result<Term, Utf8Error> {
    let filename_atom = atoms::filename().encode(env);
    let signatures_atom = atoms::signatures().encode(env);

    let filename = string_or_null!(verification_result.filename(), env)?;

    let signatures: Term = verification_result.signatures()
        .map(| signature | {
            transform_signature(env, signature)
        })
        .fold(Ok(Vec::new()), | acc, signature | {
            match acc {
                Err(error) => Err(error),
                Ok(mut acc_inner) => match signature {
                    Err(error) => Err(error),
                    Ok(signature_ok) => {
                        acc_inner.push(signature_ok);
                        Ok(acc_inner)
                    }
                }
            }
        })?
        .encode(env);

    Ok(
        elixir_struct::make_ex_struct(env, "Elixir.ExGpgme.Results.VerificationResult").ok().unwrap()
            .map_put(filename_atom, filename).ok().unwrap()
            .map_put(signatures_atom, signatures).ok().unwrap()
    )
}
