mod common;

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("vpn-server supports Linux and macOS only");

fn main() -> std::process::ExitCode {
    common::server_main()
}
