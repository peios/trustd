//! Arbitrary bytes as control-channel requests and replies. Everyone may
//! connect to trustd's socket, so this decoder sees untrusted input.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(request) = trust_core::Request::decode(data) {
        assert_eq!(
            trust_core::Request::decode(&request.encode()).unwrap(),
            request
        );
    }
    if let Ok(reply) = trust_core::Reply::decode(data) {
        let _ = trust_core::Reply::decode(&reply.encode()).unwrap();
    }
    let _ = trust_core::recv(&mut &data[..]);
});
