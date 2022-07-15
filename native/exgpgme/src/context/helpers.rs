pub mod atoms {
    atoms! {
        ok,
        error
    }
}

macro_rules! try_gpgme {
    ($expr:expr, $env:expr) => (match $expr {
        Ok(val) => val,
        Err(err) => {
            return Ok((::context::helpers::atoms::error(), err.description().into_owned()).encode($env))
        }
    })
}

macro_rules! decode_context_result {
    ($name:ident, $env:ident) => (
        match String::from_utf8($name) {
            Ok(string) => Ok((::context::helpers::atoms::ok(), string).encode($env)),
            Err(_) => Ok((::context::helpers::atoms::error(), String::from("Could not decode cyphertext to utf8")).encode($env))
        }
    )
}
