use rustler::resource::ResourceArc;
use rustler::Error;
use gpgme::keys::Key;

pub struct KeyResource {
    pub key: Key
}

pub fn wrap_key(key: Key) -> ResourceArc<KeyResource> {
    ResourceArc::new(KeyResource{
        key: key
    })
}

pub fn keys_not_empty(key_length: usize) -> Result<(), Error> {
    if key_length < 1 {
        return Err(Error::BadArg);
    } else {
        Ok(())
    }
}

#[macro_export]
macro_rules! unpack_key_list {
    ($keys:ident, $arg:expr) => (
        let keys_with_errors: Vec<ResourceArc<keys::KeyResource>> = $arg
            .decode::<ListIterator>()?
            .map(| key_arg | { key_arg.decode::<ResourceArc<keys::KeyResource>>() })
            .collect::<NifResult<Vec<ResourceArc<keys::KeyResource>>>>()?;

        let $keys: Vec<&Key> = keys_with_errors
            .iter()
            .map(| ref key_arc | &key_arc.key)
            .collect();
    );
}
