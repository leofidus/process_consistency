use std::{
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
};

use crate::{error::Error, Region};

pub fn get_executable_regions(
    skip_libs: bool,
    include_writable_code: bool,
) -> Result<Vec<Region>, Error> {
    let mut regions = vec![];
    let path = std::path::Path::new("/proc/self/maps");
    let file = File::open(path).map_err(|e| Error::ProcFsUnavailable {
        source: e,
        path: path.to_owned(),
    })?;

    let filter = if skip_libs {
        std::env::current_exe().ok()
    } else {
        None
    };

    for line in BufReader::new(file).lines() {
        let line = line.map_err(|e| Error::ProcFsUnavailable {
            source: e,
            path: path.to_owned(),
        })?;
        let segments: Vec<_> = line.split_whitespace().collect();
        if !segments[1].starts_with("r-x")
            && !(include_writable_code && segments[1].starts_with("rwx"))
        {
            continue;
        }
        let (start, end) = segments[0]
            .split_once('-')
            .ok_or(Error::ProcFsFormatError {
                path: path.to_owned(),
            })?;
        let start = usize::from_str_radix(start, 16).map_err(|_| Error::ProcFsFormatError {
            path: path.to_owned(),
        })? as *const u8;
        let end = usize::from_str_radix(end, 16).map_err(|_| Error::ProcFsFormatError {
            path: path.to_owned(),
        })? as *const u8;

        let source = segments
            .get(5)
            .copied()
            .ok_or(Error::ProcFsFormatError {
                path: path.to_owned(),
            })?
            .to_owned();

        if let Some(filter_path) = &filter {
            if Path::new(&source) != filter_path {
                continue;
            }
        }

        regions.push(Region { start, end, source })
    }
    Ok(regions)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_combinations() {
        println!("{:#?}", get_executable_regions(false, false));
        println!("----");
        println!("{:#?}", get_executable_regions(true, false));
        assert!(get_executable_regions(false, false).unwrap().len() > 2);
        assert!(get_executable_regions(false, true).unwrap().len() > 2);
        assert!(get_executable_regions(true, false).unwrap().len() <= 2);
        assert!(get_executable_regions(true, true).unwrap().len() <= 2);
    }
}
