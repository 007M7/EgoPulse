use std::{env, ffi::OsString, path::Path};

/// A per-child PATH for native shell hosts. Packaged WindowsApps executables
/// can be inaccessible to the separate Windows sandbox user. Prefer the
/// ordinary PowerShell 7 installation when it exists; change no global state.
pub fn desktop_powershell_path() -> Option<OsString> {
    let directory = std::path::PathBuf::from(env::var_os("ProgramFiles")?)
        .join("PowerShell")
        .join("7");
    if !directory.join("pwsh.exe").is_file() {
        return None;
    }
    prepend_desktop_shell(&directory, &env::var_os("PATH")?)
}

fn prepend_desktop_shell(directory: &Path, current: &std::ffi::OsStr) -> Option<OsString> {
    let mut paths = vec![directory.to_owned()];
    paths.extend(env::split_paths(current).filter(|path| {
        !path.as_os_str().is_empty()
            && !path
                .to_string_lossy()
                .eq_ignore_ascii_case(&directory.to_string_lossy())
            && !path
                .components()
                .any(|part| part.as_os_str().eq_ignore_ascii_case("WindowsApps"))
    }));
    env::join_paths(paths).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desktop_shell_path_excludes_packaged_aliases_without_dropping_other_tools() {
        let desktop = Path::new(r"C:\Program Files\PowerShell\7");
        let original = OsString::from(
            r"C:\Program Files\WindowsApps\Microsoft.PowerShell_7\;C:\Tools\git\bin;C:\Users\test\AppData\Local\Microsoft\WindowsApps;C:\Program Files\PowerShell\7;C:\Tools\WindowsApps-backup",
        );
        let result = prepend_desktop_shell(desktop, &original).expect("valid PATH");
        let parts: Vec<_> = env::split_paths(&result).collect();
        assert_eq!(
            parts,
            vec![
                desktop.to_owned(),
                Path::new(r"C:\Tools\git\bin").to_owned(),
                Path::new(r"C:\Tools\WindowsApps-backup").to_owned()
            ]
        );
        assert!(
            original
                .to_string_lossy()
                .contains("Microsoft.PowerShell_7")
        );
    }
}
