#![deny(unsafe_op_in_unsafe_fn)]

use std::{collections::HashMap, time::Instant};

use error::Error;

#[cfg(linux)]
pub mod linux;
#[cfg(windows)]
pub mod windows;

pub mod error;

#[cfg(feature = "blake3")]
type Hash = [u8; 32];
#[cfg(all(not(feature = "blake3"), feature = "crc64"))]
type Hash = u64;
#[cfg(all(not(feature = "blake3"), not(feature = "crc64")))]
compile_error!("either feature blake3 or crc64 has to be enabled");

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
pub struct Region {
    pub start: *const u8,
    pub end: *const u8,
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
        return blake3::hash(slice).into();
        #[cfg(all(not(feature = "blake3"), feature = "crc64"))]
        {
            let mut digest = crc64fast::Digest::new();
            digest.write(slice);
            digest.sum64()
        }
    }
}

#[derive(Default, Clone, Debug)]
struct CheckerConfig {
    search_once: bool,
    skip_libs: bool,
    check_period: std::time::Duration,
    include_writable_code: bool,
}

#[derive(Clone, Debug)]
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

    /// start running checks
    pub fn run(&self, error_callback: ErrorCallback) -> Result<Never, Error> {
        run_checker(&self.config, error_callback)
    }

    /// start benchmark
    pub fn benchmark(&self) -> Result<BenchmarkResult, Error> {
        run_benchmark(&self.config)
    }
}

impl Default for ProcessConsistencyChecker {
    fn default() -> Self {
        Self::new()
    }
}

/// details about an encountered memory inconsistency
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
/// see https://doc.rust-lang.org/std/primitive.never.html
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BenchmarkResult {
    scan_time: std::time::Duration,
    hash_time: std::time::Duration,
    scanned_bytes: isize,
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
        scanned_bytes: regions
            .into_iter()
            .map(|r| unsafe { r.end.offset_from(r.start) })
            .sum(),
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
