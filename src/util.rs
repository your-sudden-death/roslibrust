use std::env;
use std::path::{Path, PathBuf};
use walkdir::{DirEntry, WalkDir};

/// Identifier for ros data files which is combination of package_name and path
#[derive(Debug)]
pub struct RosFile {
    pub package_name: String,
    pub path: PathBuf,
}

/// Searches in all sub-folders of a directory for files matching the supplied predicate
/// Only applicable for finding files within packages
/// Returns both file and package it belongs to.
// TODO figure out / test for how this handles symlinks and recursion?
pub fn recursive_find_files(path: &Path, predicate: fn(&DirEntry) -> bool) -> Vec<RosFile> {
    WalkDir::new(path)
        .follow_links(true)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| predicate(e))
        .map(|e| e.path().to_path_buf())
        .map(|e| {
            let pkg_name = find_package_from_path(&e);
            RosFile {
                path: e,
                package_name: pkg_name,
            }
        })
        .collect()
}

/// Finds package name be walking up directory until package.xml is found
/// Panics if package.xml is not found
pub fn find_package_from_path(e: &PathBuf) -> String {
    let mut package_name: Option<String> = None;
    for dir in e.ancestors() {
        if dir.join("package.xml").exists() {
            package_name = Some(
                dir.into_iter()
                    .last()
                    .unwrap()
                    .to_string_lossy()
                    .to_string(),
            );
        }
    }
    if package_name.is_none() {
        panic!(
            "Found ros file, but could not determine package name: {:?}",
            e
        );
    }
    package_name.unwrap()
}

pub fn recursive_find_msg_files(path: &Path) -> Vec<RosFile> {
    recursive_find_files(path, |e| e.file_name().to_string_lossy().ends_with(".msg"))
}

pub fn recursive_find_srv_files(path: &Path) -> Vec<RosFile> {
    recursive_find_files(path, |e| e.file_name().to_string_lossy().ends_with(".srv"))
}

pub fn recursive_find_action_files(path: &Path) -> Vec<RosFile> {
    recursive_find_files(path, |e| {
        e.file_name().to_string_lossy().ends_with(".action")
    })
}

/// Looks up all messages installed in ros paths
pub fn get_installed_msgs() -> Vec<RosFile> {
    let rpp = env::var("ROS_PACKAGE_PATH").expect("ROS_PACKAGE_PATH env var not defined");
    let rpp = rpp + concat!(":", env!("CARGO_MANIFEST_DIR"), "/std_msgs");

    // Assuming unix path delimiter, please don't ask me to make this work on windows...
    let paths = rpp.split(":");

    let mut res: Vec<RosFile> = vec![];
    for path in paths {
        res.append(&mut recursive_find_msg_files(Path::new(path)));
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_installed_msgs_test() {
        let v = get_installed_msgs();
        print!("Installed msgs: {:?}", v);
    }
}
