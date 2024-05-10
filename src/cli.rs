use core::fmt;
use std::{io, path::PathBuf, time::Duration};
use std::any::Any;
use std::cell::OnceCell;
use std::ffi::{CStr, CString};
use std::fmt::Write;
use std::io::{ErrorKind, Read};
use std::marker::PhantomData;
use std::sync::OnceLock;

#[cfg(target_os = "android")]
use android_logger::Config;
use android_logger::{AndroidLogger, PlatformLogWriter};
use anyhow::{Ok, Result};

use clap::{Parser, Subcommand};
use clap::builder::Str;
use log::{Level, Log, trace};
use log::LevelFilter;
use tracing::instrument::WithSubscriber;
use tracing::subscriber::DefaultGuard;
use tracing_subscriber::fmt::Layer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::Registry;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;

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

struct PlatformLogWriterWrapper {
    level: Level,
    tag: CString,
}

impl PlatformLogWriterWrapper {
    fn get_writer(&mut self) -> PlatformLogWriter {
        PlatformLogWriter::new(None, self.level, &self.tag)
    }
}

impl io::Write for PlatformLogWriterWrapper {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let len = buf.len();
        let mut writer = self.get_writer();
        writer.write_str(&String::from_utf8_lossy(buf)).map_err(|e| io::Error::from(ErrorKind::Other))?;
        writer.flush();
        Result::Ok(len)
    }

    fn flush(&mut self) -> io::Result<()> {
        Result::Ok(())
    }
}

static LOG_GUARD: OnceLock<DefaultGuard> = OnceLock::new();

pub fn run() -> Result<()> {
    if cfg!(target_os = "android") {
        let tag = "InjectTool";
        let config = Config::default()
            .with_max_level(LevelFilter::Trace) // limit log level
            .with_tag(tag); // logs will show under mytag tag
        android_logger::init_once(config);
        let dispatcher = tracing_subscriber::FmtSubscriber::builder()
            .with_writer(move || {
                let tag_cstr = CString::new(tag).unwrap();
                PlatformLogWriterWrapper { level: Level::Trace, tag: tag_cstr }
            })
            .with_ansi(false)
            .without_time()
            .with_level(false)
            .finish();
        LOG_GUARD.get_or_init(|| tracing::subscriber::set_default(dispatcher));
    };

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
