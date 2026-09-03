use std::ffi::{c_char, c_int, c_void, CString};
use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

type RunFunction = unsafe extern "C" fn(*const c_char) -> c_int;

const PRODUCT_BANNER: &str =
    "Autobricks VPN 1.0\nCopyright © 2026 Autobricks.co.kr. All rights reserved.";

fn library_path() -> io::Result<PathBuf> {
    if let Some(path) = std::env::var_os("AUTOBRICKS_VPN_LIBRARY") {
        return Ok(path.into());
    }
    let directory = std::env::current_exe()?
        .parent()
        .ok_or_else(|| io::Error::other("launcher executable has no parent directory"))?
        .to_path_buf();
    #[cfg(target_os = "windows")]
    let name = "autobricks_vpn.dll";
    #[cfg(target_os = "macos")]
    let name = "libautobricks_vpn.dylib";
    #[cfg(all(unix, not(target_os = "macos")))]
    let name = "libautobricks_vpn.so";
    Ok(directory.join(name))
}

enum Command {
    Help,
    Run(String),
}

fn usage(program: &str) -> String {
    format!(
        "autobricks-vpn {program}\n\n\
         Usage:\n  {program} --config <FILE>\n\n\
         Options:\n  -c, --config <FILE>  Path to the VPN configuration file\n  -h, --help           Show this help and exit\n\n\
         Environment:\n  AUTOBRICKS_VPN_LIBRARY  Override the dynamic library path"
    )
}

fn parse_arguments(arguments: impl IntoIterator<Item = String>) -> Result<Command, String> {
    let mut arguments = arguments.into_iter();
    let mut config = None;
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "-h" | "--help" => return Ok(Command::Help),
            "-c" | "--config" => {
                if config.is_some() {
                    return Err("--config may only be specified once".into());
                }
                let value = arguments
                    .next()
                    .ok_or_else(|| format!("{argument} requires a file path"))?;
                if value.is_empty() {
                    return Err("--config path must not be empty".into());
                }
                config = Some(value);
            }
            _ if argument.starts_with("--config=") => {
                if config.is_some() {
                    return Err("--config may only be specified once".into());
                }
                let value = argument.trim_start_matches("--config=");
                if value.is_empty() {
                    return Err("--config path must not be empty".into());
                }
                config = Some(value.to_owned());
            }
            _ => return Err(format!("unknown argument: {argument}")),
        }
    }
    config
        .map(Command::Run)
        .ok_or_else(|| "missing required option: --config <FILE>".into())
}

fn run(symbol: &[u8], config: &str) -> io::Result<()> {
    let library = DynamicLibrary::open(&library_path()?)?;
    let run: RunFunction = unsafe { library.symbol(symbol)? };
    let config = CString::new(config)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "config path contains NUL"))?;
    let result = unsafe { run(config.as_ptr()) };
    // The runtime installs signal/console handlers whose code lives in the library.
    // Keep it loaded until process termination so those callbacks never dangle.
    std::mem::forget(library);
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "VPN library returned status {result}"
        )))
    }
}

fn launch(program: &str, symbol: &[u8]) -> ExitCode {
    println!("{PRODUCT_BANNER}");
    match parse_arguments(std::env::args().skip(1)) {
        Ok(Command::Help) => {
            println!("{}", usage(program));
            ExitCode::SUCCESS
        }
        Ok(Command::Run(config)) => match run(symbol, &config) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{program}: {error}");
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            eprintln!("{program}: {error}\n\n{}", usage(program));
            ExitCode::from(2)
        }
    }
}

#[allow(dead_code)]
pub fn client_main() -> ExitCode {
    launch("vpn-client", b"autobricks_vpn_client_run")
}

#[allow(dead_code)]
pub fn server_main() -> ExitCode {
    launch("vpn-server", b"autobricks_vpn_server_run")
}

struct DynamicLibrary(*mut c_void);

#[cfg(unix)]
impl DynamicLibrary {
    fn open(path: &Path) -> io::Result<Self> {
        use std::os::unix::ffi::OsStrExt;
        let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "library path contains NUL")
        })?;
        let handle = unsafe { libc::dlopen(path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        if handle.is_null() {
            Err(io::Error::other(dynamic_loader_error()))
        } else {
            Ok(Self(handle))
        }
    }

    unsafe fn symbol<T: Copy>(&self, name: &[u8]) -> io::Result<T> {
        let name = CString::new(name)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "symbol contains NUL"))?;
        libc::dlerror();
        let symbol = libc::dlsym(self.0, name.as_ptr());
        let error = libc::dlerror();
        if !error.is_null() {
            let message = std::ffi::CStr::from_ptr(error)
                .to_string_lossy()
                .into_owned();
            return Err(io::Error::other(message));
        }
        if symbol.is_null() {
            return Err(io::Error::other("dynamic symbol address is null"));
        }
        Ok(std::mem::transmute_copy(&symbol))
    }
}

#[cfg(unix)]
fn dynamic_loader_error() -> String {
    let error = unsafe { libc::dlerror() };
    if error.is_null() {
        "dynamic loader error".into()
    } else {
        unsafe { std::ffi::CStr::from_ptr(error) }
            .to_string_lossy()
            .into_owned()
    }
}

#[cfg(unix)]
impl Drop for DynamicLibrary {
    fn drop(&mut self) {
        unsafe {
            libc::dlclose(self.0);
        }
    }
}

#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
    fn LoadLibraryW(path: *const u16) -> *mut c_void;
    fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
    fn FreeLibrary(module: *mut c_void) -> i32;
}

#[cfg(windows)]
impl DynamicLibrary {
    fn open(path: &Path) -> io::Result<Self> {
        use std::os::windows::ffi::OsStrExt;
        let path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let handle = unsafe { LoadLibraryW(path.as_ptr()) };
        if handle.is_null() {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(handle))
        }
    }

    unsafe fn symbol<T: Copy>(&self, name: &[u8]) -> io::Result<T> {
        let name = CString::new(name)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "symbol contains NUL"))?;
        let symbol = GetProcAddress(self.0, name.as_ptr().cast());
        if symbol.is_null() {
            Err(io::Error::last_os_error())
        } else {
            Ok(std::mem::transmute_copy(&symbol))
        }
    }
}

#[cfg(windows)]
impl Drop for DynamicLibrary {
    fn drop(&mut self) {
        unsafe {
            FreeLibrary(self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_arguments, Command};

    #[test]
    fn parses_config_options() {
        assert!(matches!(
            parse_arguments(["--config".into(), "custom.ini".into()]),
            Ok(Command::Run(path)) if path == "custom.ini"
        ));
        assert!(matches!(
            parse_arguments(["--config=other.ini".into()]),
            Ok(Command::Run(path)) if path == "other.ini"
        ));
    }

    #[test]
    fn handles_help_without_config() {
        assert!(matches!(
            parse_arguments(["--help".into()]),
            Ok(Command::Help)
        ));
    }

    #[test]
    fn rejects_missing_or_unknown_arguments() {
        assert!(parse_arguments(Vec::<String>::new()).is_err());
        assert!(parse_arguments(["client.ini".into()]).is_err());
        assert!(parse_arguments(["--unknown".into()]).is_err());
    }
}
