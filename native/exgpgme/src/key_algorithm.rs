use rustler::{Env, Term, Encoder};
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

pub fn transform_key_algorithm(env: Env, algorithm: KeyAlgorithm) -> Term {
    match algorithm {
        KeyAlgorithm::Rsa => atoms::rsa().encode(env),
        KeyAlgorithm::RsaEncrypt => atoms::rsa_encrypt().encode(env),
        KeyAlgorithm::RsaSign => atoms::rsa_sign().encode(env),
        KeyAlgorithm::ElgamalEncrypt => atoms::elgamal_encrypt().encode(env),
        KeyAlgorithm::Dsa => atoms::dsa().encode(env),
        KeyAlgorithm::Ecc => atoms::ecc().encode(env),
        KeyAlgorithm::Elgamal => atoms::elgamal().encode(env),
        KeyAlgorithm::Ecdsa => atoms::ecdsa().encode(env),
        KeyAlgorithm::Ecdh => atoms::ecdh().encode(env),
        KeyAlgorithm::Eddsa => atoms::eddsa().encode(env),
        KeyAlgorithm::Other(other) => (atoms::other(), other).encode(env),
    }
}
