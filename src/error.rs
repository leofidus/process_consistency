#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// A system call failed unexpectedly
    #[error("Syscall {syscall} returned unexpected Error code {code}: {message}")]
    SysCallError {
        syscall: String,
        code: i32,
        message: String,
    },
    #[error("Unable to read from procfs under {path}: {source}")]
    ProcFsUnavailableError {
        #[source]
        source: std::io::Error,
        path: std::path::PathBuf,
    },
    #[error("Unexpected format in {path}")]
    ProcFsFormatError { path: std::path::PathBuf },
}

#[cfg(windows)]
pub(crate) fn win_get_last_error(syscall: &str) -> Error {
    let error = windows::core::Error::from_win32();
    Error::SysCallError {
        syscall: syscall.into(),
        code: error.code().0,
        message: error.message().to_string_lossy(),
    }
}
