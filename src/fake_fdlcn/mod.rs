use std::ffi::{c_int, c_void, CStr, CString};

use anyhow::{anyhow, Error};
use libc::c_char;

#[link(name = "fake_dlfcn")]
extern "C" {
    fn dlopen_ex(filename: *const c_char, flags: c_int) -> *mut c_void;
    fn dlsym_ex(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    fn dlclose_ex(handle: *mut c_void) -> c_int;
    fn dlerror_ex() -> *const c_char;
}

pub struct FakeDlfcn {
    handle: Option<*mut c_void>,
}

impl FakeDlfcn {
    pub fn dlopen(filename: &str, flags: i32) -> anyhow::Result<Self> {
        let c_str = CString::new(filename)?;
        let handle = unsafe {
            dlopen_ex(c_str.as_ptr(), flags)
        };
        if handle.is_null() {
            let err = Self::dlerror().unwrap_or("dlerror failed".to_owned());
            return Err(anyhow!("dlopen {} failed; {}", filename, err));
        }
        Ok(Self { handle: Some(handle) })
    }

    fn get_handle(&self) -> anyhow::Result<*mut c_void> {
        self.handle.ok_or(Error::msg("can't get handle"))
    }

    pub fn dlsym(&self, symbol: &str) -> anyhow::Result<usize> {
        let c_str = CString::new(symbol)?;
        let handle = self.get_handle()?;
        unsafe {
            let addr = dlsym_ex(handle, c_str.as_ptr());
            if addr.is_null() {
                return Err(anyhow!("dlsym {} failed", symbol));
            }
            Ok(addr as usize)
        }
    }

    pub fn dlclose(&mut self) -> anyhow::Result<()> {
        unsafe {
            if let Some(handle) = self.handle.take() {
                let ret = dlclose_ex(handle);
                if ret != 0 {
                    return Err(anyhow!("dlclose failed, ret: {}", ret));
                }
            }
        }
        Ok(())
    }

    pub fn dlerror() -> anyhow::Result<String> {
        unsafe {
            CStr::from_ptr(dlerror_ex()).to_str().map(Into::into).map_err(Into::into)
        }
    }
}

impl Drop for FakeDlfcn {
    fn drop(&mut self) {
        self.dlclose().unwrap();
    }
}