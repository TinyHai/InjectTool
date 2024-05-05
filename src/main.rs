mod cli;
mod inject;
mod process_wrapper;
mod ptrace_wrapper;

mod android_os;
mod sys_lib;
mod fake_fdlcn;
mod selinux;

fn main() -> anyhow::Result<()> {
    cli::run()
}

mod test {

    #[test]
    fn test_run() {
        use crate::cli;
        // cli::run().unwrap();
    }

    #[test]
    fn test_get_so_path() {
        use crate::process_wrapper::ProcessWrapper;

        let process_wrapper = ProcessWrapper::myself();
        let ret = process_wrapper.get_so_path("libc");
        println!("{}", ret.unwrap_or(String::from("None")));
    }

    #[test]
    fn test_find_pid_by_cmd() {
        use std::time::Instant;
        use std::time::Duration;
        use crate::inject::find_pid_by_cmd;

        let start = Instant::now();
        let pid = find_pid_by_cmd("clash", Duration::from_secs(60));
        println!("speed {}ms", start.elapsed().as_millis());
        assert!(pid.is_ok());
        let pid = pid.unwrap();
        println!("clash pid = {}", pid);
    }
}
