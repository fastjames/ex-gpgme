use rustler::Atom;
use gpgme::results::PkaTrust;

mod atoms {
    atoms! {
        unknown,
        bad,
        okay,
        other
    }
}

#[derive(NifUntaggedEnum)]
pub enum PkaTrustResult {
    Atom(Atom),
    Tuple((Atom, u32))
}

pub fn transform_pka_trust(trust: PkaTrust) -> PkaTrustResult {
    match trust {
        PkaTrust::Unknown => PkaTrustResult::Atom(atoms::unknown()),
        PkaTrust::Bad => PkaTrustResult::Atom(atoms::bad()),
        PkaTrust::Okay => PkaTrustResult::Atom(atoms::okay()),
        PkaTrust::Other(other) => PkaTrustResult::Tuple((atoms::other(), other)),
    }
}
