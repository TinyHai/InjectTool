#![cfg(target_arch = "aarch64")]

use std::{
    cell::RefCell,
    cmp::min,
    mem::{size_of, size_of_val, MaybeUninit},
    ops::{Deref, DerefMut},
};
use std::ffi::CStr;
use std::ops::Add;

use anyhow::{anyhow, Ok};
use log::trace;
use libc::{
    c_void, pid_t, ptrace, waitpid, PTRACE_ATTACH, PTRACE_CONT, PTRACE_DETACH,
    PTRACE_GETREGSET, PTRACE_PEEKTEXT, PTRACE_POKETEXT, PTRACE_SETREGSET, PTRACE_SYSCALL,
    WUNTRACED,
};

pub struct PtraceWrapper {
    target: pid_t,
    regs: RefCell<libc::user_regs_struct>,
    bak_regs: Option<libc::user_regs_struct>,
    libc_base: Option<usize>,
}

impl PtraceWrapper {
    pub fn attach(pid: pid_t) -> anyhow::Result<PtraceWrapper> {
        unsafe {
            let ret = ptrace(PTRACE_ATTACH, pid, 0, 0);
            if ret < 0 {
                return Err(anyhow!("attach pid: {} failed ret = {}", pid, ret));
            }
            let mut status = 0;
            waitpid(pid, &mut status, WUNTRACED);
            Self::print_wait_status(pid, status, 0)
        }

        let regs = unsafe { MaybeUninit::zeroed().assume_init() };
        Ok(Self {
            target: pid,
            regs: RefCell::new(regs),
            bak_regs: None,
            libc_base: None,
        })
    }

    pub fn continue_run(&self) -> anyhow::Result<()> {
        unsafe {
            let ret = ptrace(PTRACE_CONT, self.target, 0, 0);
            if ret < 0 {
                Err(anyhow!("continue run failed ret: {}", ret))
            } else {
                Ok(())
            }
        }
    }

    pub fn call(
        &self,
        fun_name: &str,
        fun_addr: *mut c_void,
        parameters: &[u64],
    ) -> anyhow::Result<u64> {
        trace!("call {}", fun_name);
        let mut regs = self.regs.borrow_mut();
        self.get_regs(regs.deref_mut())?;
        self.call_internal(fun_addr, parameters, regs.deref_mut())?;
        self.get_regs(regs.deref_mut())?;
        trace!(
            "target: {} returned from {}, return value = {{0x{:X}, {}}}, pc = 0x{:X?}",
            self.target,
            fun_name,
            self.get_retval(regs.deref()),
            self.get_retval(regs.deref()),
            self.get_pc(regs.deref())
        );
        Ok(self.get_retval(regs.deref()))
    }

    pub fn set_libc_base(&mut self, libc_base: usize) {
        self.libc_base.replace(libc_base);
    }

    #[inline(always)]
    fn print_wait_status(target: pid_t, status: i32, res: i32) {
        let is_stopped = libc::WIFSTOPPED(status);
        let stop_sig = if is_stopped {
            libc::WSTOPSIG(status)
        } else {
            0
        };
        trace!(
                "waitpid: {} status: {{ VALUE=0x{:X} STOPPED: {}, REASON: {}({}) }}, res: {}",
                target,
                status,
                is_stopped,
                unsafe { CStr::from_ptr(libc::strsignal(stop_sig)).to_string_lossy() },
                stop_sig,
                res
            );
    }

    #[inline(always)]
    fn get_retval(&self, regs: &libc::user_regs_struct) -> u64 {
        regs.regs[0]
    }

    #[inline(always)]
    fn get_pc(&self, regs: &libc::user_regs_struct) -> u64 {
        regs.pc
    }

    fn call_internal(
        &self,
        fun_addr: *mut c_void,
        parameters: &[u64],
        regs: &mut libc::user_regs_struct,
    ) -> anyhow::Result<()> {
        trace!(
            "regs {{ r0: 0x{:X}, r30: 0x{:X}, pc: 0x{:X}, sp: 0x{:X} }}",
            regs.regs[0], regs.regs[30], regs.pc, regs.sp
        );

        let num_parms_regs = 8;
        let parms_len = parameters.len();
        let parms_by_regs = min(num_parms_regs, parms_len);

        regs.regs[0..parms_len].copy_from_slice(parameters);

        if parms_len > num_parms_regs {
            regs.sp -= ((parms_len - num_parms_regs) * size_of::<u64>()) as u64;
            let data = &parameters[parms_by_regs..];
            self.write_data(
                regs.sp as *const u8,
                data.as_ptr() as *const u8,
                data.len() * 8,
            );
        }

        regs.pc = fun_addr as u64;

        regs.regs[30] = 0;

        if let Some(base) = self.libc_base {
            regs.regs[30] = base as u64;
        }

        self.set_regs(regs)?;
        trace!(
            "regs {{ r0: 0x{:X}, r30: 0x{:X}, pc: 0x{:X}, sp: 0x{:X} }}",
            regs.regs[0], regs.regs[30], regs.pc, regs.sp
        );
        self.continue_run()?;

        let mut status = 0;
        let res = unsafe { waitpid(self.target, &mut status, WUNTRACED) };
        Self::print_wait_status(self.target, status, res);

        while !libc::WIFSTOPPED(status) {
            self.continue_run()?;
            let res = unsafe { waitpid(self.target, &mut status, WUNTRACED) };
            Self::print_wait_status(self.target, status, res);
        }

        Ok(())
    }

    pub fn read_data(&self, src: *const u8, buf: *mut u8, size: usize) {
        union U {
            val: libc::c_long,
            chars: [libc::c_char; size_of::<libc::c_long>()],
        }
        let bytes_width = size_of::<libc::c_long>();
        let mut u = U { val: 0 };
        let cnt = size / bytes_width;
        for i in 0..cnt {
            unsafe {
                let src = src.add(i * bytes_width);
                u.val = ptrace(PTRACE_PEEKTEXT, self.target, src, 0);
                let buf = buf.add(i * bytes_width);
                buf.copy_from(&u as *const U as *const u8, size_of::<U>());
            }
        }

        let remain = size % bytes_width;
        let read = size - remain;
        if remain > 0 {
            unsafe {
                let buf = buf.add(read);
                let src = src.add(read);
                u.val = ptrace(PTRACE_PEEKTEXT, self.target, src, 0);
                buf.copy_from(&u.chars as *const _, remain);
            }
        }
    }

    pub fn write_data(&self, dest: *const u8, data: *const u8, size: usize) {
        union U {
            val: libc::c_long,
            chars: [libc::c_char; size_of::<libc::c_long>()],
        }
        let bytes_width = size_of::<libc::c_long>();
        let mut u = U { val: 0 };
        let cnt = size / bytes_width;
        for i in 0..cnt {
            unsafe {
                let dest = dest.add(i * bytes_width);
                let slice = std::slice::from_raw_parts(data.add(i * bytes_width), bytes_width);
                u.chars.copy_from_slice(slice);
                ptrace(PTRACE_POKETEXT, self.target, dest, u.val);
            }
        }

        let remain = size % bytes_width;
        let written = size - remain;
        if remain > 0 {
            let dest = unsafe { dest.add(written) };
            unsafe {
                u.val = ptrace(PTRACE_PEEKTEXT, self.target, dest, 0);
                for i in 0..remain {
                    u.chars[i] = data.add(written + i).read()
                }
                ptrace(PTRACE_POKETEXT, self.target, dest, u.val);
            }
        }
    }

    pub fn detach(&mut self) {
        if self.target != 0 {
            self.detach_internal();
        }
    }

    fn detach_internal(&mut self) {
        unsafe {
            let ret = ptrace(PTRACE_DETACH, self.target, 0, 0);
            if ret < 0 {
                trace!("detach pid: {}, ret: {}", self.target, ret);
            }
        }
        self.target = 0;
    }

    fn get_regs(&self, regs: &mut libc::user_regs_struct) -> anyhow::Result<()> {
        let io_vec = libc::iovec {
            iov_base: regs as *mut _ as *mut _,
            iov_len: size_of_val(regs),
        };
        unsafe {
            let ret = libc::ptrace(
                PTRACE_GETREGSET,
                self.target,
                1, /* NT_PRSTATUS */
                &io_vec,
            );
            if ret < 0 {
                Err(anyhow!("getregs falied ret: {}", ret))
            } else {
                Ok(())
            }
        }
    }

    fn set_regs(&self, regs: &mut libc::user_regs_struct) -> anyhow::Result<()> {
        let io_vec = libc::iovec {
            iov_base: regs as *mut _ as *mut _,
            iov_len: size_of_val(regs),
        };
        unsafe {
            let ret = libc::ptrace(
                PTRACE_SETREGSET,
                self.target,
                1, /* NT_PRSTATUS */
                &io_vec,
            );
            if ret < 0 {
                Err(anyhow!("setregs failed ret: {}", ret))
            } else {
                Ok(())
            }
        }
    }

    pub fn backup_regs(&mut self) -> anyhow::Result<()> {
        let mut regs = unsafe { MaybeUninit::<libc::user_regs_struct>::zeroed().assume_init() };
        self.get_regs(&mut regs)?;
        self.bak_regs = Some(regs);
        Ok(())
    }

    pub fn restore_regs(&mut self) -> anyhow::Result<()> {
        let mut regs = self.bak_regs.take();
        if let Some(ref mut regs) = regs {
            self.set_regs(regs)?;
        }
        Ok(())
    }
}

impl Drop for PtraceWrapper {
    fn drop(&mut self) {
        self.restore_regs().ok();
        self.detach();
    }
}
