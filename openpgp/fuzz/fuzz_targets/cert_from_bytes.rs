#![no_main]

use libfuzzer_sys::{fuzz_target, Corpus};

use openpgp::{parse::Parse, Cert};
use sequoia_openpgp as openpgp;

fuzz_target!(|data: &[u8]| -> Corpus {
    match Cert::from_bytes(data) {
        Ok(_) => Corpus::Keep,
        Err(_) => Corpus::Reject,
    }
});
