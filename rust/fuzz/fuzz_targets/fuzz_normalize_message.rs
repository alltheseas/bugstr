#![no_main]
use libfuzzer_sys::fuzz_target;
use bugstr::normalize_message;

fuzz_target!(|data: &[u8]| {
    if let Ok(msg) = std::str::from_utf8(data) {
        // Must not panic on any input
        let _ = normalize_message(msg);
    }
});
