//! A small background checker to ensure your executable code doesn't change, e.g. due to cosmic rays, rowhammer attacks, etc.
//! To this end it periodically computes a checksum of all your executable pages in memory.
//!
//! Compatible with Windows and Linux only
//!
//! # Basic Usage
//!
//! ```rust
//!   use process_consistency::ProcessConsistencyChecker;
//!   std::thread::spawn(|| {
//!     ProcessConsistencyChecker::new().run(|error| { panic!("Memory Error: {:#?}", &error) }).unwrap()
//!   });
//! ```
//!
//! The call to [run()](ProcessConsistencyChecker::run) only returns when it encounters (non-memory) errors. If a diverging hash
//! is found, the provided callback is called with additional info, including which library/binary was affected.
//!
//! # SAFETY
//!
//! This crate reads pointers from addresses provided by the operating system. This is only safe if these memory regions stay mapped into the process.
//! Gernerally this is not a problem, but if you unload a shared library (e.g. by calling FreeLibrary on Windows, or dlclose on Linux) this causes
//! race conditions that can lead to this library reading unmapped memory
//!
//! Running with [skip_libs(true)](ProcessConsistencyChecker::skip_libs) should be safe even in the presence of FreeLibrary/dlclose calls
//!
//! # Advanced Usage
//!
//! You can decrease the search radius, e.g. if you are not concerned about shared libraries (including those of your OS) you can use
//!
//! ```rust
//!   use process_consistency::ProcessConsistencyChecker;
//!   std::thread::spawn(|| {
//!     ProcessConsistencyChecker::new()
//!       .skip_libs(true)
//!       .search_once(true)
//!       .run(|error| {panic!("Memory Error: {:#?}", &error)
//!   }).unwrap()});
//! ```
//!
//! On the other hand if you are paranoid, you might find situations where also considering pages marked as executable but writable is desirable:
//!
//! ```rust
//!   use process_consistency::ProcessConsistencyChecker;
//!   std::thread::spawn(|| {
//!     ProcessConsistencyChecker::new()
//!       .include_writable_code(true)
//!       .run(|error| {panic!("Memory Error: {:#?}", &error)}).unwrap()
//!   });
//! ```
//!
//! You can also change how often the checks should be run:
//!
//! ```rust
//!   use std::time::Duration;
//!   use process_consistency::ProcessConsistencyChecker;
//!   std::thread::spawn(|| {
//!     ProcessConsistencyChecker::new()
//!       .check_period(Duration::from_secs(60))
//!       .run(|error| {panic!("Memory Error: {:#?}", &error)}).unwrap()
//!   });
//! ```
//!
//! To get a rough idea of the implications of the chosen parameters, or just to figure out which shared libraries are loaded (hint: more than you think), there is a [benchmark](ProcessConsistencyChecker::benchmark) call
//!
//! ```rust
//!   use std::time::Duration;
//!   use process_consistency::ProcessConsistencyChecker;
//!   println!("{:#?}", ProcessConsistencyChecker::new().benchmark().unwrap());
//! ```
//!
//!
//! # Hash Algorithm
//!
//!  The used hash algorithm is determined by feature flags. Blake3 is the default.
//!
//! To use with *blake3* hash use
//! ```toml
//! [dependencies]
//! process_consistency = "0.1.0"
//! ```
//!
//! To use with *crc64* hash use
//! ```toml
//! [dependencies]
//! process_consistency = { version = "0.1.0", default-features = false, features = ["crc64"] }
//! ```
//!
//! Blake3 is a cryptographically strong hash, but if you are just worried about cosmic rays you get about a 2x speedup with
//! crc64 (in release mode!, in debug mode blake3 is faster). Crc64 also has slightly fewer dependencies
//!
//!

#![deny(unsafe_op_in_unsafe_fn)]

use std::{collections::HashMap, time::Instant};

use error::Error;

#[cfg(unix)]
mod linux;
#[cfg(windows)]
mod windows;

pub mod error;

#[cfg(feature = "blake3")]
type HashInner = [u8; 32];
#[cfg(all(not(feature = "blake3"), feature = "crc64"))]
type HashInner = u64;
#[cfg(all(not(feature = "blake3"), not(feature = "crc64")))]
compile_error!("either feature blake3 or crc64 has to be enabled");

/// Hash of a [Region](Region)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Hash(HashInner);

impl Hash {
    /// return inner value. Note that its type changes depending on the hash algorithm chosen by feature flags
    pub fn inner(self) -> HashInner {
        self.0
    }
}

/// A hashed memory region
#[derive(Debug, Hash, PartialEq, Eq, Clone)]
pub struct Region {
    /// first address of the region
    pub start: *const u8,
    /// last address of the region + 1
    pub end: *const u8,
    /// where does this code come from (usually a valid Path)
    pub source: String,
}

struct RegionHash {
    hash: Hash,
    computed_at: std::time::Instant,
}

impl Region {
    /// compute hash of a memory region
    ///
    /// # SAFETY
    /// this is only safe if the module is still loaded, otherwise this might dereference and access unmapped memory
    /// there seems to be no mechanism to ensure this, other than making the entire appliation pinky-promise never to call
    /// FreeLibrary, dlclose or similar
    unsafe fn compute_hash(&self) -> Hash {
        // SAFETY: this should be safe iff the module hasn't been unloaded yet.
        // but there's no mechanism to ensure this
        let slice = unsafe {
            std::slice::from_raw_parts(self.start, self.end.offset_from(self.start) as usize)
        };

        #[cfg(feature = "blake3")]
        return Hash(blake3::hash(slice).into());
        #[cfg(all(not(feature = "blake3"), feature = "crc64"))]
        {
            let mut digest = crc64fast::Digest::new();
            digest.write(slice);
            Hash(digest.sum64())
        }
    }
}

#[derive(Default, Clone, Debug, Hash, PartialEq, Eq)]
struct CheckerConfig {
    search_once: bool,
    skip_libs: bool,
    check_period: std::time::Duration,
    include_writable_code: bool,
}

/// Config Builder
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct ProcessConsistencyChecker {
    config: CheckerConfig,
}

impl ProcessConsistencyChecker {
    pub fn new() -> Self {
        Self {
            config: CheckerConfig {
                check_period: std::time::Duration::from_secs(1),
                ..Default::default()
            },
        }
    }

    /// if set to true, discovery of code regions is only run once (Default: false)
    ///
    /// this is a reasonable optimization if you are sure you won't load dynamic libraries after `run` was called
    pub fn search_once(&mut self, search_once: bool) -> &mut Self {
        self.config.search_once = search_once;
        self
    }

    /// if set to true, only inspect code regions that belong to the binary itself, skipping dynamic libraries (Default: false)
    pub fn skip_libs(&mut self, skip_libs: bool) -> &mut Self {
        self.config.skip_libs = skip_libs;
        self
    }

    /// how often checks should be run (default: every second)
    pub fn check_period(&mut self, check_period: std::time::Duration) -> &mut Self {
        self.config.check_period = check_period;
        self
    }

    /// also consider code mapped with write permissions, e.g. from a JIT or self-modifying code (default: false)
    pub fn include_writable_code(&mut self, include_writable_code: bool) -> &mut Self {
        self.config.include_writable_code = include_writable_code;
        self
    }

    /// start running checks. Calls error_callback whenever the hash of a memory region changes. If hashes can't be
    /// calculated returns an Error, otherwise it doesn't return
    pub fn run(&self, error_callback: ErrorCallback) -> Result<Never, Error> {
        run_checker(&self.config, error_callback)
    }

    /// start benchmark. Runs a single round of hashing and returns statistics
    pub fn benchmark(&self) -> Result<BenchmarkResult, Error> {
        run_benchmark(&self.config)
    }
}

impl Default for ProcessConsistencyChecker {
    fn default() -> Self {
        Self::new()
    }
}

/// Details about an encountered memory inconsistency
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MemoryError<'a> {
    /// the address, size and origin of the region where the error occurred
    pub region: &'a Region,
    /// the previous hash of the region
    pub old_hash: Hash,
    /// the current hash of the region
    pub new_hash: Hash,
    /// when old_hash was computed
    pub old_hash_computed_at: std::time::Instant,
}

type ErrorCallback = fn(MemoryError) -> ();

fn get_all_regions(skip_libs: bool, include_writable_code: bool) -> Result<Vec<Region>, Error> {
    #[cfg(unix)]
    return crate::linux::get_executable_regions(skip_libs, include_writable_code);
    #[cfg(windows)]
    crate::windows::get_executable_regions(skip_libs, include_writable_code)
}

/// Return type of functions that don't return
///
/// see <https://doc.rust-lang.org/std/primitive.never.html>
pub enum Never {}

fn run_checker(
    config: &CheckerConfig,
    error_callback: ErrorCallback,
    // stop: AtomicBool,
) -> Result<Never, Error> {
    let mut region_hashes: HashMap<Region, RegionHash> = HashMap::new();
    loop {
        let now = std::time::Instant::now();
        let regions = if !config.search_once || region_hashes.is_empty() {
            get_all_regions(config.skip_libs, config.include_writable_code)?
        } else {
            region_hashes.keys().cloned().collect() // todo: optimize?
        };

        for region in regions {
            let hash = unsafe { region.compute_hash() };

            // don't use entry API to avoid a copy of the region
            match region_hashes.get_mut(&region) {
                Some(entry) => {
                    // check if known region is unchanged
                    if entry.hash != hash {
                        error_callback(MemoryError {
                            region: &region,
                            old_hash: entry.hash,
                            new_hash: hash,
                            old_hash_computed_at: entry.computed_at,
                        })
                    }
                    entry.hash = hash;
                    entry.computed_at = now;
                }
                None => {
                    // add regions that are new
                    region_hashes.insert(
                        region,
                        RegionHash {
                            hash,
                            computed_at: now,
                        },
                    );
                }
            }
        }

        // remove all regions that disappeared
        region_hashes.retain(|_k, v| v.computed_at == now);

        // account for time spend execting when sleeping, only relevant if configured period is tiny
        let sleep_duration = config.check_period - now.elapsed();
        std::thread::sleep(sleep_duration);
    }
}

/// Result of a [benchmark()](ProcessConsistencyChecker::benchmark) call
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BenchmarkResult {
    /// how much time was spent finding which memory regions to hash
    scan_time: std::time::Duration,
    /// how much time was spent hashing memory regions
    hash_time: std::time::Duration,
    /// how many bytes were hashed in total
    hashed_bytes: isize,
    /// which regions were hashed (including where they come from)
    regions: Vec<Region>,
}

fn run_benchmark(config: &CheckerConfig) -> Result<BenchmarkResult, Error> {
    let t0 = Instant::now();
    let regions = get_all_regions(config.skip_libs, config.include_writable_code)?;
    let t1 = Instant::now();
    for region in &regions {
        let _ = unsafe { region.compute_hash() };
    }
    let t2 = Instant::now();

    Ok(BenchmarkResult {
        scan_time: t1 - t0,
        hash_time: t2 - t1,
        hashed_bytes: regions
            .iter()
            .map(|r| unsafe { r.end.offset_from(r.start) })
            .sum(),
        regions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        println!(
            "{:?}",
            ProcessConsistencyChecker::new().benchmark().unwrap()
        );
    }
}
