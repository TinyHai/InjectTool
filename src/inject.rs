use std::{
    ffi::CString,
    fs::{self, File},
    io::{self, BufRead, Write},
    path::PathBuf,
    ptr::null_mut,
    thread::sleep,
    time::{Duration, Instant},
};
use std::ffi::CStr;
use std::ptr::null;

use anyhow::anyhow;
use clap::arg;
use libc::{__u8, c_char, c_void, dlclose, dlerror, dlopen, dlsym, MAP_ANONYMOUS, MAP_PRIVATE, mmap, munmap, pid_t, PROT_EXEC, PROT_READ, PROT_WRITE, RTLD_GLOBAL, RTLD_NOW, tm, uintptr_t};
use log::trace;
use ndk_sys::{__ANDROID_API_M__, __ANDROID_API_N__};
use paste::paste;
use crate::fake_fdlcn::FakeDlfcn;

use crate::process_wrapper::ProcessWrapper;
#[cfg(target_arch = "aarch64")]
use crate::ptrace_wrapper::PtraceWrapper;
use crate::sys_lib::SysLib;

struct InjectHelper {
    pub target_libc_base: *mut c_void,
    mmap_addr: *mut c_void,
    munmap_addr: *mut c_void,
    dlopen_addr: *mut c_void,
    dlsym_addr: *mut c_void,
    dlclose_addr: *mut c_void,
    dlerror_addr: *mut c_void,
}

macro_rules! pub_call_it {
    ($fun_name:ident) => {
        paste! {
            pub fn [< call_ $fun_name>] (
                &self,
                ptrace_wrapper: &PtraceWrapper,
                parameters: &[u64],
            ) -> anyhow::Result<u64> {
                ptrace_wrapper.call(stringify!($fun_name), self.[< $fun_name _addr >], parameters)
            }
        }
    };
    ($($fun_name:ident),+) => {
        paste! {
            $(
                pub fn [< call_ $fun_name>] (
                    &self,
                    ptrace_wrapper: &PtraceWrapper,
                    parameters: &[u64],
                ) -> anyhow::Result<u64> {
                    ptrace_wrapper.call(stringify!($fun_name), self.[< $fun_name _addr >], parameters)
                }
            )+
        }
    }
}

macro_rules! cstr {
    ($ident:ident) => {
        CString::new(stringify!($ident)).unwrap()
    };
}

impl InjectHelper {
    fn new(pid: pid_t, sys_lib: SysLib) -> anyhow::Result<Self> {
        let target_process = ProcessWrapper::new(pid);
        let self_process = ProcessWrapper::myself();

        let mut mmap_addr = 0usize;
        let mut munmap_addr = 0usize;
        let mut dlopen_addr = 0usize;
        let mut dlsym_addr = 0usize;
        let mut dlclose_addr = 0usize;
        let mut dlerror_addr = 0usize;

        let libc_path = sys_lib.get_libc_path();
        InjectHelper::with_base(
            &self_process,
            &target_process,
            &libc_path,
            |self_base, target_base| {
                let fake_libc = FakeDlfcn::dlopen(libc_path, RTLD_NOW)?;
                mmap_addr = fake_libc.dlsym("mmap")? - self_base + target_base;
                munmap_addr = fake_libc.dlsym("munmap")? - self_base + target_base;
                Ok(())
            },
        )?;

        let os_api = crate::android_os::sdk::api().unwrap_or(0);
        trace!("os_api: {}", os_api);

        let lib_path = if os_api >= __ANDROID_API_N__ {
            sys_lib.get_libdl_path()
        } else {
            sys_lib.get_linker_path()
        };
        InjectHelper::with_base(
            &self_process,
            &target_process,
            lib_path,
            |self_base: usize, target_base: usize| {
                let fake_lib = FakeDlfcn::dlopen(lib_path, RTLD_NOW)?;
                dlopen_addr = fake_lib.dlsym("dlopen")? - self_base + target_base;
                dlsym_addr = fake_lib.dlsym("dlsym")? - self_base + target_base;
                dlclose_addr = fake_lib.dlsym("dlclose")? - self_base + target_base;
                dlerror_addr = fake_lib.dlsym("dlerror")? - self_base + target_base;
                Ok(())
            },
        )?;

        trace!("mmap_addr: 0x{:X}", mmap_addr);
        trace!("munmap_addr: 0x{:X}", munmap_addr);
        trace!("dlopen_addr: 0x{:X}", dlopen_addr);
        trace!("dlsym_addr: 0x{:X}", dlsym_addr);
        trace!("dlclose_addr: 0x{:X}", dlclose_addr);
        trace!("dlerror_addr: 0x{:X}", dlerror_addr);

        let mmap_addr = mmap_addr as *mut c_void;
        let munmap_addr = munmap_addr as *mut c_void;
        let dlopen_addr = dlopen_addr as *mut c_void;
        let dlsym_addr = dlsym_addr as *mut c_void;
        let dlclose_addr = dlclose_addr as *mut c_void;
        let dlerror_addr = dlerror_addr as *mut c_void;

        let target_libc_base = target_process.get_so_base(&libc_path).ok_or(anyhow!(
            "get base from remote {} failed",
            target_process.get_pid()
        ))?;
        Ok(Self {
            target_libc_base: target_libc_base as _,
            mmap_addr,
            munmap_addr,
            dlopen_addr,
            dlsym_addr,
            dlclose_addr,
            dlerror_addr,
        })
    }

    pub fn call_by_addr(
        ptrace_wrapper: &PtraceWrapper,
        fun_name: &str,
        fun_addr: *mut c_void,
        parameters: &[u64],
    ) -> anyhow::Result<u64> {
        ptrace_wrapper.call(fun_name, fun_addr, parameters)
    }


    #[cfg(target_arch = "aarch64")]
    pub_call_it!(mmap, munmap, dlopen, dlsym, dlclose, dlerror);

    fn with_base<F>(
        self_proc: &ProcessWrapper,
        target_proc: &ProcessWrapper,
        so_path: &str,
        block: F,
    ) -> anyhow::Result<()>
        where
            F: FnOnce(usize, usize) -> anyhow::Result<()>,
    {
        trace!("so_path: {}", so_path);
        let self_base = self_proc.get_so_base(so_path).ok_or(anyhow!(
            "get base from {} failed, pid: {}",
            so_path,
            target_proc.get_pid()
        ))?;
        trace!("self_base: 0x{:X}", self_base);
        let target_base = target_proc.get_so_base(so_path).ok_or(anyhow!(
            "get base from {} failed, pid: {}",
            so_path,
            target_proc.get_pid()
        ))?;
        trace!("target_base: 0x{:X}", target_base);
        block(self_base, target_base)
    }
}

pub fn inject_so_to_pid(pid: pid_t, so_path: &str) -> anyhow::Result<()> {
    let so_path = PathBuf::from(so_path);
    let so_path_str = CString::new(so_path.to_str()).unwrap();
    let mut parameters = [0u64; 8];
    let mut ptrace_target = PtraceWrapper::attach(pid)?;
    let sys_lib = SysLib::new(find_pid_by_cmd("zygote64", Duration::from_secs(1)).unwrap());
    trace!("{:?}", sys_lib);

    let libc_path = PathBuf::from(sys_lib.get_libc_path());
    crate::selinux::copy_file_selinux_label(&libc_path, &so_path)?;

    let inject_helper = InjectHelper::new(pid, sys_lib)?;

    ptrace_target.backup_regs()?;

    ptrace_target.set_libc_base(inject_helper.target_libc_base as usize);

    let mmap_size = 0x3000;
    let mmap_params = prepare_mmap_params(
        &mut parameters,
        null_mut(),
        mmap_size,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_PRIVATE | MAP_ANONYMOUS,
    );

    let mmap_base = inject_helper.call_mmap(&ptrace_target, mmap_params)? as *const u8;

    let so_path_bytes = so_path_str.as_bytes_with_nul();
    ptrace_target.write_data(
        mmap_base as *const _,
        so_path_bytes as *const _ as *const _,
        so_path_bytes.len(),
    );

    let dlopen_params = prepare_dlopen_params(&mut parameters, mmap_base as _, RTLD_NOW);
    let handle = inject_helper.call_dlopen(&ptrace_target, dlopen_params)? as *mut c_void;
    if handle.is_null() {
        let dlerror = inject_helper.call_dlerror(&ptrace_target, &parameters)? as *const u8;
        let mut buff = vec![];
        let mut tmp = 0u8;
        let mut count = 0usize;
        loop {
            ptrace_target.read_data(unsafe { dlerror.add(count) }, &mut tmp, 1);
            count += 1;
            if tmp == 0 {
                break;
            }
            buff.push(tmp);
        }
        trace!("dlerror: {}", String::from_utf8(buff).unwrap().as_str());
    }

    // if !handle.is_null() {
    //     let dlclose_params = prepare_dlclose_params(&mut parameters, handle);
    //     inject_helper.call_dlclose(&ptrace_target, dlclose_params)?;
    // }

    let munmap_params = prepare_munmap_params(&mut parameters, mmap_base as _, mmap_size);
    inject_helper.call_munmap(&ptrace_target, munmap_params)?;

    ptrace_target.restore_regs()?;
    Ok(())
}

#[cfg(target_arch = "aarch64")]
// pub fn inject_path_to_pid(pid: pid_t, path_to_add: &str) -> anyhow::Result<()> {
//     const PATH: &[u8] = b"PATH\0";
//
//     let mut parameters = [0u64; 8];
//     let mut ptrace_target = PtraceWrapper::attach(pid)?;
//     let inject_helper = InjectHelper::new(pid)?;
//
//     ptrace_target.backup_regs()?;
//
//     let mmap_size = 0x4000;
//     let mmap_params = prepare_mmap_params(
//         &mut parameters,
//         null_mut(),
//         mmap_size,
//         PROT_READ | PROT_WRITE | PROT_EXEC,
//         MAP_ANONYMOUS | MAP_PRIVATE,
//     );
//     let mmap_base = inject_helper.call_mmap(&ptrace_target, mmap_params)? as *mut c_void;
//
//     ptrace_target.write_data(
//         mmap_base as *const _,
//         PATH as *const _ as *const _,
//         PATH.len(),
//     )?;
//
//     let getenv_params = prepare_getenv_params(&mut parameters, mmap_base as *const _);
//     let origin_env_addr = inject_helper.call_getenv(&ptrace_target, getenv_params)? as *const u8;
//
//     let mut buff = vec![];
//     buff.write_all(path_to_add.as_bytes())?;
//     buff.push(b':');
//     let mut tmp = 0u8;
//     let mut count = 0;
//     loop {
//         ptrace_target.read_data(unsafe { origin_env_addr.add(count) }, &mut tmp, 1)?;
//         count += 1;
//         if tmp == 0 {
//             break;
//         }
//         buff.push(tmp);
//     }
//     let complete_env = String::from_utf8(buff)?;
//     trace!("will setenv: {}", &complete_env);
//     let c_str = CString::new(complete_env).unwrap();
//     let bytes_to_write = c_str.as_bytes_with_nul();
//     ptrace_target.write_data(
//         unsafe { mmap_base.add(PATH.len()) as _ },
//         bytes_to_write.as_ptr(),
//         bytes_to_write.len(),
//     )?;
//
//     let setenv_params = prepare_setenv_params(
//         &mut parameters,
//         mmap_base as _,
//         unsafe { mmap_base.add(PATH.len()) as _ },
//         1,
//     );
//     let result = inject_helper.call_setenv(&ptrace_target, setenv_params)?;
//     if result != 0 {
//         return Err(anyhow!("setenv failed, code: {}", result));
//     }
//
//     let getenv_params = prepare_getenv_params(&mut parameters, mmap_base as *const _);
//     let latest_env_addr = inject_helper.call_getenv(&ptrace_target, getenv_params)? as *const u8;
//     let mut buff = vec![];
//     let mut tmp = 0u8;
//     let mut count = 0;
//     loop {
//         ptrace_target.read_data(unsafe { latest_env_addr.add(count) }, &mut tmp, 1)?;
//         count += 1;
//         if tmp == 0 {
//             break;
//         }
//         buff.push(tmp);
//     }
//     let latest_env = String::from_utf8(buff)?;
//     trace!("lastest env: {}", latest_env);
//
//     let munmap_params = prepare_munmap_params(&mut parameters, mmap_base, mmap_size);
//     inject_helper.call_munmap(&ptrace_target, munmap_params)?;
//
//     ptrace_target.restore_regs()?;
//     Ok(())
// }
macro_rules! prepare_params {
    ($params:ident, $($arg:ident),+) => {{
        let mut idx = 0;
        $(
            ($params)[idx] = $arg as u64;
            idx += 1;
        )+
        &($params)[0..idx]
    }};
}

fn prepare_mmap_params(
    parameters: &mut [u64],
    addr: *mut c_void,
    size: usize,
    prot: i32,
    flags: i32,
) -> &[u64] {
    let fd = 0;
    let offset = 0;
    prepare_params!(parameters, addr, size, prot, flags, fd, offset)
}

fn prepare_munmap_params(
    parameters: &mut [u64],
    addr: *const c_void,
    size: usize,
) -> &[u64] {
    prepare_params!(parameters, addr, size)
}

fn prepare_dlopen_params(
    parameters: &mut [u64],
    so_path: *const c_void,
    flags: i32,
) -> &[u64] {
    prepare_params!(parameters, so_path, flags)
}

fn prepare_dlsym_params(
    parameters: &mut [u64],
    handle: *mut c_void,
    symbol: *const c_char,
) -> &[u64] {
    prepare_params!(parameters, handle, symbol)
}

fn prepare_dlclose_params(
    parameters: &mut [u64],
    handle: *mut c_void,
) -> &[u64] {
    prepare_params!(parameters, handle)
}

fn prepare_inject_entry_params(
    parameters: &mut [u64],
    arg: *mut c_void,
) -> &[u64] {
    prepare_params!(parameters, arg)
}

pub fn find_pid_by_cmd(cmd: &str, timeout: Duration) -> anyhow::Result<pid_t> {
    let clock = Instant::now();
    loop {
        if clock.elapsed() >= timeout {
            break Err(anyhow!("target pid not found due to timeout, cmd: {}", cmd));
        }
        let pid = _find_pid_by_cmd(cmd);
        if pid.is_ok() {
            break pid;
        }

        sleep(Duration::ZERO)
    }
}

fn _find_pid_by_cmd(cmd: &str) -> anyhow::Result<pid_t> {
    let mut target_pid: pid_t = 0;
    let proc_path = PathBuf::from("/proc");
    let proc_entry = fs::read_dir(&proc_path)?;

    let all_proc_entries = proc_entry
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let is_dir = entry.file_type().ok()?.is_dir();
            let is_dot_file = entry.file_name().to_string_lossy().starts_with('.');
            let is_numbers = entry
                .file_name()
                .to_string_lossy()
                .chars()
                .all(char::is_numeric);
            if is_dir && !is_dot_file && is_numbers {
                Some(entry)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    for entry in all_proc_entries {
        let cmdline_path = entry.path().join("cmdline");
        let cmdline_file = File::options().read(true).open(cmdline_path);
        match cmdline_file {
            Ok(cmd_file) => {
                let lines = io::BufReader::new(cmd_file).lines();
                for line in lines {
                    let line = line.unwrap_or_default();
                    if line.starts_with(cmd) {
                        target_pid = entry.file_name().to_string_lossy().parse().unwrap_or(0);
                        break;
                    }
                }
            }
            Err(_) => continue,
        }
    }

    if target_pid == 0 {
        Err(anyhow!("target pid not found, cmd: {}", cmd))
    } else {
        Ok(target_pid)
    }
}
