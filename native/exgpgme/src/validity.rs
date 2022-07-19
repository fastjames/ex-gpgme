use rustler::{Env, Term, Encoder};
use gpgme::Validity;

mod atoms {
    atoms! {
        unknown,
        undefined,
        never,
        marginal,
        full,
        ultimate
    }
}

pub fn transform_validity(env: Env, validity: Validity) -> Term {
    match validity {
        Validity::Unknown => atoms::unknown().encode(env),
        Validity::Undefined => atoms::undefined().encode(env),
        Validity::Never => atoms::never().encode(env),
        Validity::Marginal => atoms::marginal().encode(env),
        Validity::Full => atoms::full().encode(env),
        Validity::Ultimate => atoms::ultimate().encode(env),
    }
}
