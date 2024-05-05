use std::ops::Deref;
use libc::pid_t;
use ndk_sys::{__ANDROID_API_Q__, __ANDROID_API_R__};
use crate::process_wrapper::ProcessWrapper;

#[derive(Debug)]
pub struct SysLib {
    libc: String,
    linker: String,
    libdl: String,
    libart: String,
    libandroid_runtime: String
}

impl SysLib {
    #[cfg(target_arch = "aarch64")]
    pub fn new(pid: pid_t) -> Self {
        // let os_api = crate::android_os::sdk::api().unwrap_or(0);
        let proc = ProcessWrapper::new(pid);

        let get_lib_path = |lib_name: &str| -> String {
            proc.get_so_path(lib_name).expect(&format!("can't find {} path", lib_name))
        };

        let libc = get_lib_path("libc.so");
        let linker = get_lib_path("linker64");
        let libdl = get_lib_path("libdl.so");
        let libart = get_lib_path("libart.so");
        let libandroid_runtime = get_lib_path("libandroid_runtime.so");

        Self {
            libc,
            linker,
            libdl,
            libart,
            libandroid_runtime
        }
        // if os_api >= __ANDROID_API_R__ {
        //     Self {
        //         libc: "/apex/com.android.runtime/lib64/bionic/libc.so",
        //         linker: "/apex/com.android.runtime/bin/linker64",
        //         libdl: "/apex/com.android.runtime/lib64/bionic/libdl.so"
        //     }
        // } else if os_api >= __ANDROID_API_Q__ {
        //     Self {
        //         libc: "/apex/com.android.runtime/lib64/bionic/libc.so",
        //         linker: "/apex/com.android.runtime/bin/linker64",
        //         libdl: "/apex/com.android.runtime/lib64/bionic/libdl.so"
        //     }
        // } else {
        //     Self {
        //         libc: "/system/lib64/libc.so",
        //         linker: "/system/bin/linker64",
        //         libdl: "/system/lib64/libdl.so"
        //     }
        // }
    }

    pub fn get_libc_path(&self) -> &str {
        &self.libc
    }

    pub fn get_linker_path(&self) -> &str {
        &self.linker
    }

    pub fn get_libdl_path(&self) -> &str {
        &self.libdl
    }

    pub fn get_libart_path(&self) -> &str {
        &self.libart
    }

    pub fn get_libandroid_runtime_path(&self) -> &str {
        &self.libandroid_runtime
    }
}