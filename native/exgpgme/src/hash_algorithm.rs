use rustler::{Env, Term, Encoder};
use gpgme::HashAlgorithm;

mod atoms {
    atoms! {
        none,
        md2,
        md4,
        md5,
        sha1,
        sha224,
        sha256,
        sha384,
        sha512,
        ripe_md160,
        tiger,
        haval,
        crc32,
        crc32_rfc1510,
        crc24_rfc2440,
        other
    }
}

pub fn transform_hash_algorithm<'a>(env: Env<'a>, algorithm: HashAlgorithm) -> Term<'a> {
    match algorithm {
        HashAlgorithm::None => atoms::none().encode(env),
        HashAlgorithm::Md2 => atoms::md2().encode(env),
        HashAlgorithm::Md4 => atoms::md4().encode(env),
        HashAlgorithm::Md5 => atoms::md5().encode(env),
        HashAlgorithm::Sha1 => atoms::sha1().encode(env),
        HashAlgorithm::Sha224 => atoms::sha224().encode(env),
        HashAlgorithm::Sha256 => atoms::sha256().encode(env),
        HashAlgorithm::Sha384 => atoms::sha384().encode(env),
        HashAlgorithm::Sha512 => atoms::sha512().encode(env),
        HashAlgorithm::RipeMd160 => atoms::ripe_md160().encode(env),
        HashAlgorithm::Tiger => atoms::tiger().encode(env),
        HashAlgorithm::Haval => atoms::haval().encode(env),
        HashAlgorithm::Crc32 => atoms::crc32().encode(env),
        HashAlgorithm::Crc32Rfc1510 => atoms::crc32_rfc1510().encode(env),
        HashAlgorithm::CrC24Rfc2440 => atoms::crc24_rfc2440().encode(env),
        HashAlgorithm::Other(other) => (atoms::other(), other).encode(env),
    }
}
