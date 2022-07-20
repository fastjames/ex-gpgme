use rustler::Atom;
use gpgme::KeyAlgorithm;

mod atoms {
    atoms! {
        rsa,
        rsa_encrypt,
        rsa_sign,
        elgamal_encrypt,
        dsa,
        ecc,
        elgamal,
        ecdsa,
        ecdh,
        eddsa,
        other
    }
}

#[derive(NifUntaggedEnum)]
pub enum KeyAlgorithmResult {
    Atom(Atom),
    Tuple((Atom, u32))
}

pub fn transform_key_algorithm(algorithm: KeyAlgorithm) -> KeyAlgorithmResult {
    match algorithm {
        KeyAlgorithm::Rsa => KeyAlgorithmResult::Atom(atoms::rsa()),
        KeyAlgorithm::RsaEncrypt => KeyAlgorithmResult::Atom(atoms::rsa_encrypt()),
        KeyAlgorithm::RsaSign => KeyAlgorithmResult::Atom(atoms::rsa_sign()),
        KeyAlgorithm::ElgamalEncrypt => KeyAlgorithmResult::Atom(atoms::elgamal_encrypt()),
        KeyAlgorithm::Dsa => KeyAlgorithmResult::Atom(atoms::dsa()),
        KeyAlgorithm::Ecc => KeyAlgorithmResult::Atom(atoms::ecc()),
        KeyAlgorithm::Elgamal => KeyAlgorithmResult::Atom(atoms::elgamal()),
        KeyAlgorithm::Ecdsa => KeyAlgorithmResult::Atom(atoms::ecdsa()),
        KeyAlgorithm::Ecdh => KeyAlgorithmResult::Atom(atoms::ecdh()),
        KeyAlgorithm::Eddsa => KeyAlgorithmResult::Atom(atoms::eddsa()),
        KeyAlgorithm::Other(other) => KeyAlgorithmResult::Tuple((atoms::other(), other)),
    }
}
