use rustler::{Error};
use rustler::types::list::ListIterator;
use gpgme;
use gpgme::EncryptFlags;

pub fn arg_to_protocol(atoms: ListIterator) -> Result<EncryptFlags, Error> {
    let mut flags = EncryptFlags::empty();

    for atom in atoms {
        let name = atom.atom_to_string()?;

        flags.insert(string_to_flag(name)?);
    }

    Ok(flags)
}

pub fn string_to_flag(name: String) -> Result<EncryptFlags, Error> {
    match name.as_ref() {
      "always_trust" => Ok(gpgme::EncryptFlags::ALWAYS_TRUST),
      "expect_sign" => Ok(gpgme::EncryptFlags::EXPECT_SIGN),
      "no_compress" => Ok(gpgme::EncryptFlags::NO_COMPRESS),
      "no_encrypt_to" => Ok(gpgme::EncryptFlags::NO_ENCRYPT_TO),
      "prepare" => Ok(gpgme::EncryptFlags::PREPARE),
      "symmetric" => Ok(gpgme::EncryptFlags::SYMMETRIC),
      "throw_keyids" => Ok(gpgme::EncryptFlags::THROW_KEYIDS),
      "wrap" => Ok(gpgme::EncryptFlags::WRAP),
      _ => Err(Error::BadArg)
    }
}
