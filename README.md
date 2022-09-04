# process_consistency

A small background checker to ensure your executable code doesn't change, e.g. due to cosmic rays, rowhammer attacks, etc.
To this end it periodically computes a checksum of all your executable pages in memory.

Compatible with Windows and Linux only

[![Crates.io](https://img.shields.io/crates/v/process_consistency)](https://crates.io/crates/process_consistency)
[![Documentation](https://docs.rs/process_consistency/badge.svg)](https://docs.rs/process_consistency)
![Lines of code](https://img.shields.io/tokei/lines/github/leofidus/process_consistency)
![Crates.io](https://img.shields.io/crates/l/process_consistency)


## Basic Usage

```rust
  use process_consistency::ProcessConsistencyChecker;
  std::thread::spawn(|| {ProcessConsistencyChecker::new().run(|error| {panic!("Memory Error: {:#?}", &error)}).unwrap()});
```

The call to [run()](ProcessConsistencyChecker::run) only returns when it encounters (non-memory) errors. If a diverging hash
is found, the provided callback is called with additional info, including which library/binary was affected.

## SAFETY

This crate reads pointers from addresses provided by the operating system. This is only safe if these memory regions stay mapped into the process.
Gernerally this is not a problem, but if you unload a shared library (e.g. by calling FreeLibrary on Windows, or dlclose on Linux) this causes
race conditions that can lead to this library reading unmapped memory

Running with [skip_libs(true)](ProcessConsistencyChecker::skip_libs) should be safe even in the presence of FreeLibrary/dlclose calls

## Advanced Usage

You can decrease the search radius, e.g. if you are not concerned about shared libraries (including those of your OS) you can use

```rust
  use process_consistency::ProcessConsistencyChecker;
  std::thread::spawn(|| {ProcessConsistencyChecker::new().skip_libs(true).search_once(true).run(|error| {panic!("Memory Error: {:#?}", &error)}).unwrap()});
```

On the other hand if you are paranoid, you might find situations where also considering pages marked as executable but writable is desirable:

```rust
  use process_consistency::ProcessConsistencyChecker;
  std::thread::spawn(|| {ProcessConsistencyChecker::new().include_writable_code(true).run(|error| {panic!("Memory Error: {:#?}", &error)}).unwrap()});
```

You can also change how often the checks should be run:

```rust
  use std::time::Duration;
  use process_consistency::ProcessConsistencyChecker;
  std::thread::spawn(|| {ProcessConsistencyChecker::new().check_period(Duration::from_secs(60)).run(|error| {panic!("Memory Error: {:#?}", &error)}).unwrap()});
```

To get a rough idea of the implications of the chosen parameters, or just to figure out which shared libraries are loaded (hint: more than you think), there is a [benchmark](ProcessConsistencyChecker::benchmark) call

```rust
  use std::time::Duration;
  use process_consistency::ProcessConsistencyChecker;
  println!("{:#?}", ProcessConsistencyChecker::new().benchmark().unwrap());
```


## Hash Algorithm

 The used hash algorithm is determined by feature flags. Blake3 is the default.

To use with *blake3* hash use
```toml
[dependencies]
process_consistency = "0.1.0"
```

To use with *crc64* hash use
```toml
[dependencies]
process_consistency = { version = "0.1.0", default-features = false, features = ["crc64"] }
```

Blake3 is a cryptographically strong hash, but if you are just worried about cosmic rays you get about a 2x speedup with
crc64 (in release mode!, in debug mode blake3 is faster). Crc64 also has slightly fewer dependencies

## License

process_consistency is dual-licensed under

* Apache 2.0 license ([LICENSE-Apache](./LICENSE-Apache) or <http://www.apache.org/licenses/LICENSE-2.0>)
* MIT license ([LICENSE-MIT](./LICENSE-MIT) or <https://opensource.org/licenses/MIT>)
