use rustler::Atom;
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

pub fn transform_validity(validity: Validity) -> Atom {
    match validity {
        Validity::Unknown => atoms::unknown(),
        Validity::Undefined => atoms::undefined(),
        Validity::Never => atoms::never(),
        Validity::Marginal => atoms::marginal(),
        Validity::Full => atoms::full(),
        Validity::Ultimate => atoms::ultimate(),
    }
}
