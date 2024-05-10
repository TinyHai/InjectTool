use std::{
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
    process,
};

use libc::pid_t;
use ptrace_do::ProcessIdentifier;

pub struct ProcessWrapper {
    pid: pid_t,
}

impl ProcessWrapper {
    pub fn new(pid: pid_t) -> Self {
        Self { pid: pid }
    }

    pub fn myself() -> Self {
        Self {
            pid: process::id() as pid_t,
        }
    }

    pub fn get_pid(&self) -> pid_t {
        self.pid
    }

    pub fn get_so_base(&self, so_path: &str) -> Option<usize> {
        let pid = self.pid;
        let maps_filename = format!("/proc/{}/maps", pid);
        let maps_path = Path::new(&maps_filename);
        let maps_file = File::options().read(true).open(maps_path).ok()?;
        let maps_lines = BufReader::new(maps_file).lines();
        for line in maps_lines {
            let line = line.ok()?;
            if line.contains(so_path) {
                let end = line.find('-')?;
                let mut base = usize::from_str_radix(&line[..end], 16).ok()?;
                if base == 0x8000usize {
                    base = 0;
                }
                return Some(base);
            }
        }
        None
    }

    pub fn get_so_path(&self, name: &str) -> Option<String> {
        let pid = self.pid;
        let maps_filename = format!("/proc/{}/maps", pid);
        let maps_path = Path::new(&maps_filename);
        let maps_file = File::options().read(true).open(maps_path).ok()?;
        let maps_lines = BufReader::new(maps_file).lines();
        for line in maps_lines {
            let line = line.ok()?;
            if line.trim_end().ends_with(&name) {
                let start = line.find('/')?;
                return Some(line[start..].to_string());
            }
        }
        None
    }
}

impl ProcessIdentifier for ProcessWrapper {
    fn pid(&self) -> pid_t {
        self.pid
    }
}
