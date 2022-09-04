use windows::Win32::{
    Foundation::CloseHandle,
    System::{
        Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W,
            TH32CS_SNAPMODULE,
        },
        Memory::{
            VirtualQuery, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
            PAGE_EXECUTE_WRITECOPY,
        },
    },
};

use crate::error::{win_get_last_error, Error};

#[derive(Debug, Hash)]
pub struct Module {
    module_id: u32,
    process_id: u32,
    base_addr: *const u8,
    base_size: u32,
    module_name: String,
    exe_path: String,
}

pub(crate) fn get_executable_regions(
    skip_libs: bool,
    include_writable_code: bool,
) -> Result<Vec<crate::Region>, Error> {
    let mut res = vec![];
    for module in get_module_list(skip_libs)? {
        res.extend(module.get_executable_regions(include_writable_code)?);
    }
    Ok(res)
}

fn get_module_list(skip_libs: bool) -> Result<Vec<Module>, Error> {
    let mut res = vec![];
    unsafe {
        let handle =
            CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0).map_err(|e| Error::SysCallError {
                syscall: "CreateToolhelp32Snapshot".into(),
                code: e.code().0,
                message: e.message().to_string_lossy(),
            })?;

        let mut module = MODULEENTRY32W {
            dwSize: std::mem::size_of::<MODULEENTRY32W>() as u32, // safe to assume that struct will stay smaller than 4GB
            ..Default::default()
        };

        if !Module32FirstW(handle, &mut module).as_bool() {
            return Err(win_get_last_error("Module32FirstW"));
        }
        res.push(module.try_into()?);

        if !skip_libs {
            while Module32NextW(handle, &mut module).as_bool() {
                res.push(module.try_into()?);
            }
        }

        CloseHandle(handle);
    }
    Ok(res)
}

impl TryFrom<MODULEENTRY32W> for Module {
    type Error = Error;

    fn try_from(value: MODULEENTRY32W) -> Result<Self, Self::Error> {
        Ok(Module {
            module_id: value.th32ModuleID,
            process_id: value.th32ProcessID,
            base_addr: value.modBaseAddr,
            base_size: value.modBaseSize,
            module_name: String::from_utf16_lossy(
                // read until first \0, or end of buffer
                value.szModule.split(|v| *v == 0).next().unwrap(),
            ),
            exe_path: String::from_utf16_lossy(value.szExePath.split(|v| *v == 0).next().unwrap()),
        })
    }
}

impl Module {
    /// print status, protection and type flags of all pages to stdout
    pub fn debug_pages(&self) -> Result<(), Error> {
        let mut states = vec![];
        let mut protects = vec![];
        let mut types = vec![];

        for offset in (0..self.base_size).step_by(4096) {
            let pos = unsafe { self.base_addr.offset(offset as isize) };
            let mut info: MEMORY_BASIC_INFORMATION = Default::default();
            unsafe {
                if 0 == VirtualQuery(
                    pos as *const _,
                    &mut info,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                ) {
                    return Err(win_get_last_error("VirtualQuery"));
                }
            }
            states.push(info.State.0);
            protects.push(info.Protect.0);
            types.push(info.Type.0);
        }

        println!("state {}", debug_print_vec(&states));
        println!("prote {}", debug_print_vec(&protects));
        println!("types {}", debug_print_vec(&types));

        Ok(())
    }

    /// get all regions of this module that are executable
    pub(crate) fn get_executable_regions(
        &self,
        include_writable_code: bool,
    ) -> Result<Vec<crate::Region>, Error> {
        let mut regions = vec![];

        let module_end = unsafe { self.base_addr.add(self.base_size as usize) };
        let mut pos = self.base_addr;
        loop {
            let mut info: MEMORY_BASIC_INFORMATION = Default::default();
            unsafe {
                if 0 == VirtualQuery(
                    pos as *const _,
                    &mut info,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                ) {
                    return Err(win_get_last_error("VirtualQuery"));
                }
            }
            let segment_end = unsafe { info.BaseAddress.add(info.RegionSize) as *const u8 };
            let segment_end = segment_end.min(module_end);
            if info.Protect | PAGE_EXECUTE_READ == PAGE_EXECUTE_READ
                || info.Protect | PAGE_EXECUTE_WRITECOPY == PAGE_EXECUTE_WRITECOPY
                || (info.Protect | PAGE_EXECUTE_READWRITE == PAGE_EXECUTE_READWRITE
                    && include_writable_code)
            {
                regions.push(crate::Region {
                    start: pos,
                    end: segment_end,
                    source: self.exe_path.clone(),
                });
            }
            if segment_end >= module_end {
                break;
            }
            pos = segment_end;
        }

        Ok(regions)
    }
}

fn debug_print_vec(v: &[u32]) -> String {
    let list: Vec<_> = v.iter().map(|x| format!("{:02x}", x)).collect();
    list.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_combinations() {
        println!("{:#?}", get_executable_regions(false, false));
        println!("----");
        println!("{:#?}", get_executable_regions(true, false));
        assert!(get_executable_regions(false, false).unwrap().len() > 1);
        assert!(get_executable_regions(false, true).unwrap().len() > 1);
        assert!(get_executable_regions(true, false).unwrap().len() <= 1);
        assert!(get_executable_regions(true, true).unwrap().len() <= 1);
    }
}
