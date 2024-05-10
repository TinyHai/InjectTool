use std::{
    ffi::CString,
    fs::{self, File},
    io::{self, BufRead},
    path::PathBuf,
    ptr::null_mut,
    thread::sleep,
    time::{Duration, Instant},
};
use std::ffi::c_void;

use anyhow::anyhow;
use libc::{MAP_ANONYMOUS, MAP_PRIVATE, pid_t, PROT_EXEC, PROT_READ, PROT_WRITE, RTLD_NOW};
use log::trace;
use ndk_sys::__ANDROID_API_N__;
use paste::paste;
use ptrace_do::{ProcessFrame, ProcessIdentifier, RawProcess, TracedProcess, UserRegs};

use crate::fake_fdlcn::FakeDlfcn;
use crate::process_wrapper::ProcessWrapper;
use crate::sys_lib::SysLib;

struct InjectHelper {
    pub target_libc_base: usize,
    mmap_addr: usize,
    munmap_addr: usize,
    dlopen_addr: usize,
    dlsym_addr: usize,
    dlclose_addr: usize,
    dlerror_addr: usize,
}

macro_rules! pub_call_it {
    ($fun_name:ident) => {
        paste! {
            pub fn [< call_ $fun_name>] <T> (
                &self,
                proc_frame: ProcessFrame<T>,
                parameters: &[usize],
            ) -> anyhow::Result<(UserRegs, ProcessFrame<T>)> where T: ProcessIdentifier {
                Self::call_by_addr(proc_frame, stringify!($fun_name), self.[< $fun_name _addr >], parameters)
            }
        }
    };
    ($($fun_name:ident),+) => {
        paste! {
            $(
                pub fn [< call_ $fun_name>] <T> (
                    &self,
                    proc_frame: ProcessFrame<T>,
                    parameters: &[usize],
                ) -> anyhow::Result<(UserRegs, ProcessFrame<T>)> where T: ProcessIdentifier {
                    Self::call_by_addr(proc_frame, stringify!($fun_name), self.[< $fun_name _addr >], parameters)
                }
            )+
        }
    }
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

    pub fn call_by_addr<T>(
        proc_frame: ProcessFrame<T>,
        fun_name: &str,
        fun_addr: usize,
        parameters: &[usize],
    ) -> anyhow::Result<(UserRegs, ProcessFrame<T>)> where T: ProcessIdentifier {
        trace!("call {}, addr: 0x{:X}", fun_name, fun_addr);
        Ok(proc_frame.invoke_remote(fun_addr, 0, parameters)?)
    }


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
    let so_path = fs::canonicalize(PathBuf::from(so_path)).unwrap();
    let so_path_str = CString::new(so_path.to_str().unwrap()).unwrap();

    let zygote_pid = if cfg!(any(target_arch = "arm", target_arch = "x86")) {
        find_pid_by_cmd("zygote", Duration::from_secs(1))
    } else {
        find_pid_by_cmd("zygote64", Duration::from_secs(1))
    }.unwrap();

    let sys_lib = SysLib::new(zygote_pid);
    trace!("{:?}", sys_lib);

    let libc_path = PathBuf::from(sys_lib.get_libc_path());
    crate::selinux::copy_file_selinux_label(&libc_path, &so_path)?;

    let inject_helper = InjectHelper::new(pid, sys_lib)?;

    let mut parameters = Vec::<usize>::new();
    let traced_proc = TracedProcess::attach(RawProcess::new(pid))?;
    let proc_frame = traced_proc.next_frame()?;
    // ptrace_target.set_libc_base(inject_helper.target_libc_base as usize);

    let mmap_size = 0x3000;
    let mmap_params = prepare_mmap_params(
        &mut parameters,
        0,
        mmap_size,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_PRIVATE | MAP_ANONYMOUS,
    );

    let (regs, mut proc_frame) = inject_helper.call_mmap(proc_frame, mmap_params)?;
    let mmap_base = regs.return_value();

    let so_path_bytes = so_path_str.as_bytes_with_nul();
    (&mut proc_frame).write_memory(mmap_base, so_path_bytes)?;

    let dlopen_params = prepare_dlopen_params(&mut parameters, mmap_base as _, RTLD_NOW);
    let (regs, proc_frame) = inject_helper.call_dlopen(proc_frame, dlopen_params)?;
    let handle = regs.return_value();

    let proc_frame = if handle == 0 {
        let (regs, proc_frame) = inject_helper.call_dlerror(proc_frame, &[])?;
        let dlerror = regs.return_value();
        let mut buff = vec![0u8; 256];
        let read = proc_frame.read_memory_mut(dlerror, &mut buff)?;
        buff.truncate(read);
        if let Some(idx) = buff.iter().rposition(|&x| x == 0) {
            buff.truncate(idx)
        }
        trace!("dlerror: {}", String::from_utf8_lossy(&buff));
        proc_frame
    } else {
        proc_frame
    };

    // if handle == 0 {
    //     let dlclose_params = prepare_dlclose_params(&mut parameters, handle);
    //     inject_helper.call_dlclose(proc_frame, dlclose_params)?;
    // }

    let munmap_params = prepare_munmap_params(&mut parameters, mmap_base as _, mmap_size);
    let (_, _) = inject_helper.call_munmap(proc_frame, munmap_params)?;

    Ok(())
}

macro_rules! prepare_params {
    ($params:ident, $($arg:ident),+) => {{
        ($params).clear();
        $(
            ($params).push(($arg) as _);
        )+
        &($params)[..]
    }};
}

fn prepare_mmap_params(
    parameters: &mut Vec<usize>,
    addr: usize,
    size: usize,
    prot: i32,
    flags: i32,
) -> &[usize] {
    let fd = 0;
    let offset = 0;
    prepare_params!(parameters, addr, size, prot, flags, fd, offset)
}

fn prepare_munmap_params(
    parameters: &mut Vec<usize>,
    addr: usize,
    size: usize,
) -> &[usize] {
    prepare_params!(parameters, addr, size)
}

fn prepare_dlopen_params(
    parameters: &mut Vec<usize>,
    so_path_addr: usize,
    flags: i32,
) -> &[usize] {
    prepare_params!(parameters, so_path_addr, flags)
}

fn prepare_dlsym_params(
    parameters: &mut Vec<usize>,
    handle: usize,
    symbol: usize,
) -> &[usize] {
    prepare_params!(parameters, handle, symbol)
}

fn prepare_dlclose_params(
    parameters: &mut Vec<usize>,
    handle: usize,
) -> &[usize] {
    prepare_params!(parameters, handle)
}

fn prepare_inject_entry_params(
    parameters: &mut Vec<usize>,
    arg: usize,
) -> &[usize] {
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
