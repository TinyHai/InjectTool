use std::io;
use std::io::{BufRead, Error};
use std::os::unix::prelude::CommandExt;
use std::path::Path;
use std::process::{Command, ExitStatus};
use anyhow::anyhow;
use log::trace;

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn get_file_selinux_label<P>(path: P) -> anyhow::Result<String> where P: AsRef<Path> {
    let path = std::fs::canonicalize(path).unwrap();
    let file_name = path.file_name().unwrap().to_str().unwrap();
    let path_str = path.to_str().unwrap();
    let mut cmd = Command::new("ls");
    cmd.arg("-Z").arg(path_str);

    trace!("{:?}", &cmd);

    let out = cmd.output()?;
    if !out.status.success() {
        return Err(anyhow!("{}", &String::from_utf8_lossy(&out.stderr)));
    } else {
        for line in out.stdout.lines().flat_map(|l| l.ok()) {
            trace!("{}", &line);
            if line.ends_with(file_name) {
                let mut iter = line.split_ascii_whitespace();
                let selinux_label = iter.next().unwrap();
                let file_name = iter.next().unwrap();
                trace!("file_name: {}, selinux_label: {}", file_name, selinux_label);
                return Ok(selinux_label.to_owned());
            }
        }
    }
    Err(anyhow!("get file selinux label failure, path: {}", path_str))
}

pub fn set_file_selinux_label<P, L>(path: P, label: L) -> anyhow::Result<()> where P: AsRef<Path>, L: AsRef<str> {
    let path = std::fs::canonicalize(path).unwrap();
    let path_str = path.to_str().unwrap();
    let label = label.as_ref();

    let mut cmd = Command::new("chcon");
    cmd.arg(label).arg(path_str);

    trace!("{:?}", &cmd);

    let out = cmd.output()?;
    if !out.status.success() {
        Err(anyhow!("{}", String::from_utf8_lossy(out.stderr.as_ref())))
    } else {
        Ok(())
    }
}

pub fn copy_file_selinux_label<P>(from: P, to: P) -> anyhow::Result<()> where P: AsRef<Path> {
    let from_path = std::fs::canonicalize(from).unwrap();
    let to_path = std::fs::canonicalize(to).unwrap();
    if !from_path.is_file() || !to_path.is_file() {
        return Err(anyhow!("unsupported"));
    }
    let selinux_label = get_file_selinux_label(from_path)?;
    set_file_selinux_label(to_path, selinux_label)
}
