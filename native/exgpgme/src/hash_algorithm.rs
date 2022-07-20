use rustler::Atom;
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

#[derive(NifUntaggedEnum)]
pub enum HashAlgorithmResult {
    Atom(Atom),
    Tuple((Atom, u32))
}

pub fn transform_hash_algorithm(algorithm: HashAlgorithm) -> HashAlgorithmResult {
    match algorithm {
        HashAlgorithm::None => HashAlgorithmResult::Atom(atoms::none()),
        HashAlgorithm::Md2 => HashAlgorithmResult::Atom(atoms::md2()),
        HashAlgorithm::Md4 => HashAlgorithmResult::Atom(atoms::md4()),
        HashAlgorithm::Md5 => HashAlgorithmResult::Atom(atoms::md5()),
        HashAlgorithm::Sha1 => HashAlgorithmResult::Atom(atoms::sha1()),
        HashAlgorithm::Sha224 => HashAlgorithmResult::Atom(atoms::sha224()),
        HashAlgorithm::Sha256 => HashAlgorithmResult::Atom(atoms::sha256()),
        HashAlgorithm::Sha384 => HashAlgorithmResult::Atom(atoms::sha384()),
        HashAlgorithm::Sha512 => HashAlgorithmResult::Atom(atoms::sha512()),
        HashAlgorithm::RipeMd160 => HashAlgorithmResult::Atom(atoms::ripe_md160()),
        HashAlgorithm::Tiger => HashAlgorithmResult::Atom(atoms::tiger()),
        HashAlgorithm::Haval => HashAlgorithmResult::Atom(atoms::haval()),
        HashAlgorithm::Crc32 => HashAlgorithmResult::Atom(atoms::crc32()),
        HashAlgorithm::Crc32Rfc1510 => HashAlgorithmResult::Atom(atoms::crc32_rfc1510()),
        HashAlgorithm::CrC24Rfc2440 => HashAlgorithmResult::Atom(atoms::crc24_rfc2440()),
        HashAlgorithm::Other(other) => HashAlgorithmResult::Tuple((atoms::other(), other)),
    }
}
