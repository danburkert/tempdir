// Copyright 2013 The Rust Project Developers.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![feature(env, fs, io, old_io, old_path, path, os, std_misc)]

extern crate rand;

use rand::Rng;
use std::path::{Path, PathBuf};
use std::ffi::{OsString, AsOsStr, OsStr};
use std::old_io;
use std::env;
use std::fs;
use std::io;
use std::old_path;

/// Returns the path to a temporary directory.
///
/// On Unix, returns the value of the 'TMPDIR' environment variable if it is
/// set, otherwise for non-Android it returns '/tmp'. If Android, since there
/// is no global temporary folder (it is usually allocated per-app), we return
/// '/data/local/tmp'.
///
/// On Windows, returns the value of, in order, the 'TMP', 'TEMP',
/// 'USERPROFILE' environment variable  if any are set and not the empty
/// string. Otherwise, tmpdir returns the path to the Windows directory.
pub fn temp_dir() -> PathBuf {

    fn var_nonempty(v: &str) -> Option<PathBuf> {
        match env::var(v) {
            Ok(x) =>
                if x.is_empty() {
                    None
                } else {
                    Some(PathBuf::new(&x))
                },
            _ => None
        }
    }

    #[cfg(unix)]
    fn lookup() -> PathBuf {
        let default = if cfg!(target_os = "android") {
            PathBuf::new("/data/local/tmp")
        } else {
            PathBuf::new("/tmp")
        };

        var_nonempty("TMPDIR").unwrap_or(default)
    }

    #[cfg(windows)]
    fn lookup() -> PathBuf {
        var_nonempty("TMP").or(
            var_nonempty("TEMP").or(
                var_nonempty("USERPROFILE").or(
                   var_nonempty("WINDIR")))).unwrap_or(Path::new("C:\\Windows"))
    }

    lookup()
}

// TODO: this can be removed once std::env::current_dir returns the new Result type
fn to_new_error(error: old_io::IoError) -> io::Error {

    fn to_new_error_kind(kind: &old_io::IoErrorKind) -> io::ErrorKind {
        match *kind {
            old_io::IoErrorKind::OtherIoError => io::ErrorKind::Other,
            old_io::IoErrorKind::EndOfFile => io::ErrorKind::Other,
            old_io::IoErrorKind::FileNotFound => io::ErrorKind::FileNotFound,
            old_io::IoErrorKind::PermissionDenied => io::ErrorKind::PermissionDenied,
            old_io::IoErrorKind::ConnectionFailed => io::ErrorKind::Other,
            old_io::IoErrorKind::Closed => io::ErrorKind::Other,
            old_io::IoErrorKind::ConnectionRefused => io::ErrorKind::ConnectionRefused,
            old_io::IoErrorKind::ConnectionReset => io::ErrorKind::ConnectionReset,
            old_io::IoErrorKind::ConnectionAborted => io::ErrorKind::ConnectionAborted,
            old_io::IoErrorKind::NotConnected => io::ErrorKind::NotConnected,
            old_io::IoErrorKind::BrokenPipe => io::ErrorKind::BrokenPipe,
            old_io::IoErrorKind::PathAlreadyExists => io::ErrorKind::PathAlreadyExists,
            old_io::IoErrorKind::PathDoesntExist => io::ErrorKind::PathDoesntExist,
            old_io::IoErrorKind::MismatchedFileTypeForOperation => io::ErrorKind::MismatchedFileTypeForOperation,
            old_io::IoErrorKind::ResourceUnavailable => io::ErrorKind::ResourceUnavailable,
            old_io::IoErrorKind::IoUnavailable => io::ErrorKind::Other,
            old_io::IoErrorKind::InvalidInput => io::ErrorKind::InvalidInput,
            old_io::IoErrorKind::TimedOut => io::ErrorKind::TimedOut,
            old_io::IoErrorKind::ShortWrite(_) => io::ErrorKind::Other,
            old_io::IoErrorKind::NoProgress => io::ErrorKind::Other,
        }
    }

    match error {
        old_io::IoError { kind, desc, detail } => io::Error::new(to_new_error_kind(&kind), desc, detail)
    }
}

/// A wrapper for a path to temporary directory implementing automatic
/// scope-based deletion.
///
///# Examples
///
/// ```no_run
/// use std::path::Path;
/// use tempdir::TempDir;
///
/// {
///     // create a temporary directory
///     let temp_dir = match TempDir::new("myprefix") {
///         Ok(dir) => dir,
///         Err(e) => panic!("couldn't create temporary directory: {}", e)
///     };
///
///     // get the path of the temporary directory without affecting the wrapper
///     let path = temp_dir.path();
///
///     println!("The path of temporary directory is {}", path.display());
///
///     // the temporary directory is automatically removed when temp_dir goes
///     // out of scope at the end of the block
/// }
/// {
///     // create a temporary directory, this time using a custom path
///     let temp_dir = match TempDir::new_in(&Path::new("/tmp/best/custom/path"), "myprefix") {
///         Ok(dir) => dir,
///         Err(e) => panic!("couldn't create temporary directory: {}", e)
///     };
///
///     // get the path of the temporary directory and disable automatic deletion in the wrapper
///     let path = temp_dir.into_inner();
///
///     println!("The path of the not-so-temporary directory is {}", path.display());
///
///     // the temporary directory is not removed here
///     // because the directory is detached from the wrapper
/// }
/// {
///     // create a temporary directory
///     let temp_dir = match TempDir::new("myprefix") {
///         Ok(dir) => dir,
///         Err(e) => panic!("couldn't create temporary directory: {}", e)
///     };
///
///     // close the temporary directory manually and check the result
///     match temp_dir.close() {
///         Ok(_) => println!("success!"),
///         Err(e) => panic!("couldn't remove temporary directory: {}", e)
///     };
/// }
/// ```
pub struct TempDir {
    path: Option<PathBuf>,
}

/// How many times should we (re)try finding an unused random name? It should be
/// enough that an attacker will run out of luck before we run out of patience.
const NUM_RETRIES: u32 = 1 << 31;

/// How many characters should we include in a random file name? It needs to
/// be enough to dissuade an attacker from trying to preemptively create names
/// of that length, but not so huge that we unnecessarily drain the random number
/// generator of entropy.
const NUM_RAND_CHARS: usize = 12;

impl TempDir {

    /// Attempts to make a temporary directory inside of `os::tmpdir()` whose
    /// name will have the prefix `prefix`. The directory will be automatically
    /// deleted once the returned wrapper is destroyed.
    ///
    /// If no directory can be created, `Err` is returned.
    pub fn new<P: ?Sized>(prefix: &P) -> io::Result<TempDir>
        where P: AsOsStr
    {
        TempDir::new_in(&temp_dir(), prefix)
    }

    /// Attempts to make a temporary directory inside of `tmpdir` whose name
    /// will have the prefix `prefix`. The directory will be automatically
    /// deleted once the returned wrapper is destroyed.
    ///
    /// If no directory can be created, `Err` is returned.
    pub fn new_in<P: ?Sized>(tmpdir: &Path, prefix: &P) -> io::Result<TempDir>
        where P: AsOsStr
    {
        if tmpdir.is_relative() {
            let cur_dir: old_path::Path = match env::current_dir() {
                Err(err) => return Err(to_new_error(err)),
                Ok(path) => path,
            };
            let cur_dir: &Path = Path::new(&cur_dir);
            return TempDir::new_in(&cur_dir.join(tmpdir), prefix);
        }

        let mut rng = rand::thread_rng();
        for _ in 0..NUM_RETRIES {
            let suffix: String = rng.gen_ascii_chars().take(NUM_RAND_CHARS).collect();
            let leaf: OsString = if prefix.as_os_str() != OsStr::from_str("") {
                let mut s = OsString::new();
                s.push_os_str(prefix.as_os_str());
                s.push_os_str(OsStr::from_str("."));
                s.push_os_str(suffix.as_os_str());
                s
            } else {
                // If we're given an empty string for a prefix, then creating a
                // directory starting with "." would lead to it being
                // semi-invisible on some systems.
                suffix.as_os_str().to_os_string()
            };
            let path: PathBuf = tmpdir.join(&leaf);
            match fs::create_dir(&path) {
                Ok(_) => return Ok(TempDir { path: Some(path) }),
                Err(ref e) if e.kind() == io::ErrorKind::PathAlreadyExists => (),
                Err(e) => return Err(e)
            }
        }

        Err(io::Error::new(io::ErrorKind::PathAlreadyExists, "Exhausted", None))
    }

    /// Unwrap the wrapped `std::path::Path` from the `TempDir` wrapper.
    /// This discards the wrapper so that the automatic deletion of the
    /// temporary directory is prevented.
    pub fn into_inner(mut self) -> PathBuf {
        self.path.take().unwrap()
    }

    /// Access the wrapped `std::path::Path` to the temporary directory.
    pub fn path<'a>(&'a self) -> &'a Path {
        &self.path.as_ref().unwrap()
    }

    /// Close and remove the temporary directory.
    ///
    /// Although `TempDir` removes the directory on drop, in the destructor any errors are ignored.
    /// To detect errors cleaning up the temporary directory, call `close` instead.
    pub fn close(self) -> io::Result<()> {
        fs::remove_dir_all(&self.into_inner())
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        for p in self.path.iter() {
            let _ = fs::remove_dir_all(p);
        }
    }
}

#[cfg(test)]
mod test {

    use std::fs::{self, PathExt};
    use std::path::PathBuf;
    use std::thread;

    use super::*;

    #[test]
    fn test_tempdir_prefix() {
        let temp_dir = TempDir::new("test_tempdir_prefix").unwrap();
        assert!(temp_dir.path().to_str().unwrap().contains("test_tempdir_prefix"));
    }

    #[test]
    fn test_tempdir_drop() {
        let temp_dir = TempDir::new("test_tempdir_drop").unwrap();
        let path = temp_dir.path().to_path_buf();

        assert!(path.exists());
        drop(temp_dir);
        assert!(!path.exists());
    }

    #[test]
    fn test_tempdir_send() {
        let temp_dir: TempDir = TempDir::new("test_tempdir_send").unwrap();
        let path: PathBuf = temp_dir.path().to_path_buf();

        let f = move || { assert!(temp_dir.path().exists()) };
        let _ = thread::scoped(f).join();
        assert!(!path.exists());
    }

    #[test]
    fn test_tempdir_close() {
        let temp_dir = TempDir::new("test_tempdir_drop").unwrap();
        let path = temp_dir.path().to_path_buf();

        assert!(path.exists());
        temp_dir.close().unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn test_tempdir_into_inner() {
        let temp_dir: TempDir = TempDir::new("test_tempdir_drop").unwrap();
        let path: PathBuf = temp_dir.into_inner();
        assert!(path.exists());
        let _ = fs::remove_dir(&path);
    }
}
