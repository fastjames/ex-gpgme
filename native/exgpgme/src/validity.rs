use rustler::{Env, Term, Encoder};
use gpgme::Validity;

mod atoms {
    rustler_atoms! {
        atom unknown;
        atom undefined;
        atom never;
        atom marginal;
        atom full;
        atom ultimate;
    }
}

pub fn transform_validity<'a>(env: Env<'a>, validity: Validity) -> Term<'a> {
    match validity {
        Validity::Unknown => atoms::unknown().encode(env),
        Validity::Undefined => atoms::undefined().encode(env),
        Validity::Never => atoms::never().encode(env),
        Validity::Marginal => atoms::marginal().encode(env),
        Validity::Full => atoms::full().encode(env),
        Validity::Ultimate => atoms::ultimate().encode(env),
    }
}
