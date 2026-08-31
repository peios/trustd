//! Arbitrary bytes as control-channel requests and replies. Everyone may
//! connect to trustd's socket, so this decoder sees untrusted input.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(request) = libtrust::Request::decode(data) {
        assert_eq!(libtrust::Request::decode(&request.encode()).unwrap(), request);
    }
    if let Ok(reply) = libtrust::Reply::decode(data) {
        let _ = libtrust::Reply::decode(&reply.encode()).unwrap();
    }
    let _ = libtrust::recv(&mut &data[..]);
});
