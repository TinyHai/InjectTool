use std::{
    fs::{self, set_permissions, DirBuilder, Permissions},
    os::unix::{prelude::PermissionsExt, process::CommandExt},
    path::{Path, PathBuf},
    time::Duration,
};

#[cfg(target_os = "android")]
use android_logger::Config;
use anyhow::{anyhow, Ok, Result};

use clap::{Parser, Subcommand};
use log::trace;
use log::LevelFilter;

use crate::inject::{find_pid_by_cmd, inject_so_to_pid};

#[derive(Parser, Debug)]
#[command(author, version = "1.0", about, long_about = None)]
struct Args {
    #[command(subcommand)]
    commands: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Inject {
        /// Target app package
        #[arg(short, long)]
        cmd: String,
        /// The so path
        #[arg(short, long)]
        so_path: String,
        /// The timeout seconds
        #[arg(short, long, default_value_t = 10)]
        timeout: u32,
    },
    Selinux {
        /// The so path
        #[arg(short, long)]
        so_path: String,
        /// The selinux label to set
        #[arg(short, long)]
        label: Option<String>,
    },
}

pub fn run() -> Result<()> {
    #[cfg(target_os = "android")]
    android_logger::init_once(
        Config::default()
            .with_max_level(LevelFilter::Trace) // limit log level
            .with_tag("SK_CLI"), // logs will show under mytag tag
    );

    let args = Args::parse();
    match args.commands {
        Commands::Inject {
            cmd,
            so_path,
            timeout,
        } => {
            trace!(
                "inject cmd: {}, so_path: {}, timeout:{}",
                cmd,
                so_path,
                timeout
            );
            let pid = find_pid_by_cmd(&cmd, Duration::from_secs(timeout.into()))?;
            inject_so_to_pid(pid, &so_path)?;
            trace!("inject pid {} success", pid);
            Ok(())
        }
        Commands::Selinux { so_path, label } => {
            let path = PathBuf::from(so_path);
            match label {
                None => {
                    println!("{}", crate::selinux::get_file_selinux_label(path)?);
                    Ok(())
                }
                Some(label) => {
                    crate::selinux::set_file_selinux_label(&path, &label)?;
                    println!("set {} to {} success", label, path.to_str().unwrap());
                    Ok(())
                }
            }
        }
    }
}
