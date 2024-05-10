use libc::pid_t;

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
    pub fn new(pid: pid_t) -> Self {
        let proc = ProcessWrapper::new(pid);

        let get_lib_path = |lib_name: &str| -> String {
            proc.get_so_path(lib_name).expect(&format!("can't find {} path", lib_name))
        };

        let libc = get_lib_path("libc.so");
        #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
        let linker = get_lib_path("linker64");
        #[cfg(any(target_arch = "arm", target_arch = "x86"))]
        let linker = get_lib_path("linker");
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