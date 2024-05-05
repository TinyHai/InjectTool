use std::ffi::CString;

use libc::__system_property_get;
use ndk_sys::atol;

#[cfg(target_os = "android")]
pub fn api() -> Option<u32> {
    unsafe {
        let name = CString::new("ro.build.version.sdk").ok()?;
        let mut value = [0u8; 8];
        if __system_property_get(name.as_ptr(), value.as_mut_ptr()) > 0 {
            let api = atol(value.as_ptr());
            Some(api as _)
        } else {
            None
        }
    }
}