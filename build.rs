//! Generate a compile-time asset table from the production Vite bundle.
use std::{
    env, fs, io,
    path::{Path, PathBuf},
};

/// Require a frontend build and generate byte inclusions for every bundled asset.
fn main() -> io::Result<()> {
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("Cargo manifest directory"));
    let dist = root.join("ui/dist");
    println!("cargo:rerun-if-changed=ui/dist");
    if !dist.join("index.html").is_file() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "UI bundle missing; run mise install && mise exec -- pnpm install --frozen-lockfile && mise exec -- pnpm build:ui before cargo build",
        ));
    }
    let mut paths = Vec::new();
    collect_assets(&dist, &mut paths)?;
    paths.sort();
    let mut table = String::from(
        "/// Production UI assets embedded into every build profile.\nstatic ASSETS: &[(&str, &[u8])] = &[\n",
    );
    for path in paths {
        let name = path.strip_prefix(&dist).expect("asset inside UI bundle").to_string_lossy();
        table.push_str(&format!("    ({name:?}, include_bytes!({:?})),\n", path.to_string_lossy()));
    }
    table.push_str("];\n");
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo output directory"));
    fs::write(output.join("ui_assets.rs"), table)
}

/// Recursively collect regular asset files, propagating filesystem failures.
fn collect_assets(directory: &Path, paths: &mut Vec<PathBuf>) -> io::Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_dir() {
            collect_assets(&entry.path(), paths)?;
        } else if kind.is_file() {
            paths.push(entry.path());
        }
    }
    Ok(())
}
