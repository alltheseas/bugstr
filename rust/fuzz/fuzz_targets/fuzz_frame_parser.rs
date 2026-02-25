#![no_main]
use libfuzzer_sys::fuzz_target;
use bugstr::{extract_frame_parts, is_in_app_frame};

fuzz_target!(|data: &[u8]| {
    if let Ok(line) = std::str::from_utf8(data) {
        // Must not panic on any input
        if let Some((method, file)) = extract_frame_parts(line) {
            // is_in_app_frame must also not panic
            let _ = is_in_app_frame(&file, &method);
        }
    }
});
