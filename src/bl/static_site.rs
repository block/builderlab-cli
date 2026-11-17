//! Package a built static site directory as a Hot Pod static artifact.
//!
//! `bl apps deploy --dir` uses this so a caller can publish a plain build
//! output folder (for example `dist/`) without writing a manifest or tarball.
//! The archive is deterministic: the same directory always produces the same
//! bytes, so a repeated deploy uploads an identical bundle.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use flate2::write::GzEncoder;
use flate2::{Compression, GzBuilder};
use serde_json::json;

pub const MANIFEST_NAME: &str = "hotpod.manifest.json";
const SITE_ROOT: &str = "public";
const INDEX_NAME: &str = "index.html";
// These match the Compose artifact validator's limits.
const MAX_ENTRIES: usize = 100_000;
const MAX_TOTAL_BYTES: u64 = 2 << 30;
// Fixed metadata keeps the archive byte-for-byte reproducible.
const ENTRY_MTIME: u64 = 0;
const FILE_MODE: u32 = 0o644;
const DIR_MODE: u32 = 0o755;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotFoundHandling {
    /// Unknown paths return 404, with the site's root `404.html` when present.
    NotFound,
    /// Unknown paths serve the root `index.html` for client-side routing.
    Spa,
}

impl NotFoundHandling {
    fn manifest_value(self) -> &'static str {
        match self {
            NotFoundHandling::NotFound => "404",
            NotFoundHandling::Spa => "spa",
        }
    }
}

#[derive(Debug)]
pub struct PackagedSite {
    pub archive: tempfile::NamedTempFile,
    pub files: usize,
    pub content_bytes: u64,
    pub archive_bytes: u64,
    pub skipped: Vec<String>,
    pub not_found_handling: NotFoundHandling,
}

impl PackagedSite {
    pub fn path(&self) -> &Path {
        self.archive.path()
    }

    pub fn summary(&self, source: &Path) -> serde_json::Value {
        json!({
            "source_dir": source.display().to_string(),
            "runtime_profile": "static",
            "not_found_handling": self.not_found_handling.manifest_value(),
            "files": self.files,
            "content_bytes": self.content_bytes,
            "archive_bytes": self.archive_bytes,
            "skipped": self.skipped,
        })
    }
}

struct SiteEntry {
    relative: String,
    source: PathBuf,
    is_dir: bool,
    size: u64,
}

/// Build a static artifact for `app_id` from the files in `dir`.
pub fn package_static_dir(
    dir: &Path,
    app_id: &str,
    not_found_handling: NotFoundHandling,
) -> Result<PackagedSite> {
    let metadata = fs::metadata(dir)
        .with_context(|| format!("read static site directory {}", dir.display()))?;
    if !metadata.is_dir() {
        anyhow::bail!(
            "--dir must be a directory containing the built site: {}",
            dir.display()
        );
    }
    if fs::symlink_metadata(dir.join(MANIFEST_NAME)).is_ok() {
        anyhow::bail!(
            "{} contains {MANIFEST_NAME}, so it is already a Hot Pod artifact directory. \
             Pass --dir the built site files themselves (for example dist/), or package this \
             directory as artifact.tar.gz and pass that path instead.",
            dir.display()
        );
    }
    let index = fs::symlink_metadata(dir.join(INDEX_NAME));
    if !index.as_ref().is_ok_and(|metadata| metadata.is_file()) {
        anyhow::bail!(
            "{} has no {INDEX_NAME} at its root. Pass the directory your build writes the site \
             to (for example dist/ or build/), not the project directory.",
            dir.display()
        );
    }

    let mut entries = Vec::new();
    let mut skipped = Vec::new();
    collect_entries(dir, "", &mut entries, &mut skipped)?;
    let files = entries.iter().filter(|entry| !entry.is_dir).count();
    let content_bytes: u64 = entries.iter().map(|entry| entry.size).sum();
    let manifest = manifest_bytes(app_id, not_found_handling)?;
    check_archive_limits(dir, entries.len(), content_bytes, manifest.len() as u64)?;

    let mut archive = tempfile::Builder::new()
        .prefix("bl-static-site-")
        .suffix(".tar.gz")
        .tempfile()
        .context("create temporary static site artifact")?;
    write_archive(archive.as_file_mut(), &manifest, &entries)?;
    archive
        .as_file_mut()
        .flush()
        .context("flush static site artifact")?;
    let archive_bytes = archive
        .as_file()
        .metadata()
        .context("read static site artifact size")?
        .len();
    Ok(PackagedSite {
        archive,
        files,
        content_bytes,
        archive_bytes,
        skipped,
        not_found_handling,
    })
}

/// Mirrors the platform validator, which also counts the manifest and the
/// public/ directory entry, so a site at the limit fails here rather than
/// after upload.
fn check_archive_limits(
    dir: &Path,
    site_entries: usize,
    content_bytes: u64,
    manifest_bytes: u64,
) -> Result<()> {
    let archive_entries = site_entries + 2;
    if archive_entries > MAX_ENTRIES {
        anyhow::bail!(
            "{} has {site_entries} files and directories; with the manifest and {SITE_ROOT}/ \
             that is {archive_entries} archive entries, and Apps Platform accepts at most \
             {MAX_ENTRIES}",
            dir.display()
        );
    }
    let archive_bytes = content_bytes + manifest_bytes;
    if archive_bytes > MAX_TOTAL_BYTES {
        anyhow::bail!(
            "{} holds {content_bytes} bytes; with the manifest that is {archive_bytes} bytes, \
             and Apps Platform accepts at most {MAX_TOTAL_BYTES} bytes uncompressed",
            dir.display()
        );
    }
    Ok(())
}

fn manifest_bytes(app_id: &str, not_found_handling: NotFoundHandling) -> Result<Vec<u8>> {
    let manifest = json!({
        "schema": "hotpod.manifest.v1",
        "app": { "app_id": app_id },
        "runtime": {
            "profile": "static",
            "root": SITE_ROOT,
            "not_found_handling": not_found_handling.manifest_value(),
        }
    });
    let mut bytes = serde_json::to_vec_pretty(&manifest).context("serialize static manifest")?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Names a built site never serves, matched whatever the entry type:
/// - macOS metadata: `.DS_Store`, `._*` AppleDouble files, `__MACOSX/`;
/// - version control: `.git`, which is a file in worktrees and submodules;
/// - project files that `--dir .` would otherwise publish to every viewer:
///   `.env`, `.env.*` and `.envrc` secrets, and `node_modules/`.
fn is_skipped_name(name: &str) -> bool {
    matches!(name, ".DS_Store" | "__MACOSX" | ".git" | "node_modules")
        || name.starts_with("._")
        || name.starts_with(".env")
}

fn collect_entries(
    dir: &Path,
    prefix: &str,
    entries: &mut Vec<SiteEntry>,
    skipped: &mut Vec<String>,
) -> Result<()> {
    let mut children = fs::read_dir(dir)
        .with_context(|| format!("list static site directory {}", dir.display()))?
        .map(|child| child.map(|child| child.path()))
        .collect::<std::io::Result<Vec<_>>>()
        .with_context(|| format!("list static site directory {}", dir.display()))?;
    children.sort();
    for source in children {
        let name = source
            .file_name()
            .and_then(|name| name.to_str())
            .with_context(|| format!("static site path is not valid UTF-8: {}", source.display()))?
            .to_string();
        let relative = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        let metadata = fs::symlink_metadata(&source)
            .with_context(|| format!("read static site path {}", source.display()))?;
        let file_type = metadata.file_type();
        if is_skipped_name(&name) {
            skipped.push(relative);
            continue;
        }
        if file_type.is_symlink() {
            anyhow::bail!(
                "static site path {relative} is a symlink; Apps Platform artifacts can only \
                 contain regular files. Copy the target into the build output instead."
            );
        }
        if file_type.is_dir() {
            entries.push(SiteEntry {
                relative: relative.clone(),
                source: source.clone(),
                is_dir: true,
                size: 0,
            });
            collect_entries(&source, &relative, entries, skipped)?;
        } else if file_type.is_file() {
            entries.push(SiteEntry {
                relative,
                source,
                is_dir: false,
                size: metadata.len(),
            });
        } else {
            anyhow::bail!("static site path {relative} is not a regular file or directory");
        }
    }
    Ok(())
}

fn write_archive(file: &mut fs::File, manifest: &[u8], entries: &[SiteEntry]) -> Result<()> {
    // A zero gzip mtime and no file name keep the compressed bytes reproducible.
    let encoder: GzEncoder<&mut fs::File> = GzBuilder::new()
        .mtime(0)
        .write(file, Compression::default());
    let mut builder = tar::Builder::new(encoder);
    builder.mode(tar::HeaderMode::Deterministic);

    append_bytes(&mut builder, MANIFEST_NAME, manifest)?;
    append_dir(&mut builder, SITE_ROOT)?;
    for entry in entries {
        let name = format!("{SITE_ROOT}/{}", entry.relative);
        if entry.is_dir {
            append_dir(&mut builder, &name)?;
            continue;
        }
        let source = fs::File::open(&entry.source)
            .with_context(|| format!("open static site file {}", entry.source.display()))?;
        // Use the size observed during the walk; a file that changes while
        // packaging fails here instead of producing a corrupt archive.
        let mut header = file_header(entry.size);
        let reader = ExactReader {
            inner: std::io::Read::take(source, entry.size),
            remaining: entry.size,
        };
        builder
            .append_data(&mut header, &name, reader)
            .with_context(|| format!("add {name} to static site artifact"))?;
    }
    let encoder = builder
        .into_inner()
        .context("finish static site tar archive")?;
    encoder.finish().context("finish static site gzip stream")?;
    Ok(())
}

/// Fails instead of returning early EOF, so a file that shrinks while it is
/// being packaged can't leave a tar entry shorter than its header says.
struct ExactReader<R> {
    inner: R,
    remaining: u64,
}

impl<R: std::io::Read> std::io::Read for ExactReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buf)?;
        if read == 0 && self.remaining > 0 && !buf.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "static site file changed size while packaging; rebuild and retry",
            ));
        }
        self.remaining -= read as u64;
        Ok(read)
    }
}

fn file_header(size: u64) -> tar::Header {
    let mut header = tar::Header::new_ustar();
    header.set_entry_type(tar::EntryType::Regular);
    header.set_size(size);
    header.set_mode(FILE_MODE);
    header.set_mtime(ENTRY_MTIME);
    header.set_uid(0);
    header.set_gid(0);
    header
}

fn append_bytes<W: Write>(builder: &mut tar::Builder<W>, name: &str, bytes: &[u8]) -> Result<()> {
    let mut header = file_header(bytes.len() as u64);
    builder
        .append_data(&mut header, name, bytes)
        .with_context(|| format!("add {name} to static site artifact"))
}

fn append_dir<W: Write>(builder: &mut tar::Builder<W>, name: &str) -> Result<()> {
    let mut header = tar::Header::new_ustar();
    header.set_entry_type(tar::EntryType::Directory);
    header.set_size(0);
    header.set_mode(DIR_MODE);
    header.set_mtime(ENTRY_MTIME);
    header.set_uid(0);
    header.set_gid(0);
    builder
        .append_data(&mut header, format!("{name}/"), std::io::empty())
        .with_context(|| format!("add {name}/ to static site artifact"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::read::GzDecoder;
    use std::collections::BTreeMap;
    use std::io::Read;

    fn write(root: &Path, relative: &str, contents: &str) {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }

    fn site() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "index.html", "<h1>home</h1>");
        write(dir.path(), "about.html", "<h1>about</h1>");
        write(dir.path(), "404.html", "<h1>missing</h1>");
        write(dir.path(), "assets/app.js", "console.log(1)");
        write(dir.path(), ".well-known/security.txt", "Contact: x");
        dir
    }

    struct Entry {
        kind: tar::EntryType,
        mode: u32,
        mtime: u64,
        body: String,
    }

    fn read_archive(path: &Path) -> BTreeMap<String, Entry> {
        let file = fs::File::open(path).unwrap();
        let mut archive = tar::Archive::new(GzDecoder::new(file));
        let mut entries = BTreeMap::new();
        for entry in archive.entries().unwrap() {
            let mut entry = entry.unwrap();
            let name = entry.path().unwrap().to_string_lossy().into_owned();
            let header = entry.header().clone();
            let mut body = String::new();
            entry.read_to_string(&mut body).unwrap();
            entries.insert(
                name,
                Entry {
                    kind: header.entry_type(),
                    mode: header.mode().unwrap(),
                    mtime: header.mtime().unwrap(),
                    body,
                },
            );
        }
        entries
    }

    #[test]
    fn packages_site_under_public_with_static_manifest() {
        let dir = site();
        let packaged =
            package_static_dir(dir.path(), "docs-site", NotFoundHandling::NotFound).unwrap();
        let entries = read_archive(packaged.path());

        let manifest: serde_json::Value =
            serde_json::from_str(&entries[MANIFEST_NAME].body).unwrap();
        assert_eq!(
            manifest,
            json!({
                "schema": "hotpod.manifest.v1",
                "app": {"app_id": "docs-site"},
                "runtime": {"profile": "static", "root": "public", "not_found_handling": "404"}
            })
        );
        assert_eq!(entries["public/index.html"].body, "<h1>home</h1>");
        assert_eq!(entries["public/assets/app.js"].body, "console.log(1)");
        assert_eq!(
            entries["public/.well-known/security.txt"].body,
            "Contact: x"
        );
        assert_eq!(entries["public/assets/"].kind, tar::EntryType::Directory);
        assert_eq!(entries["public/assets/"].mode, DIR_MODE);
        assert_eq!(entries["public/about.html"].mode, FILE_MODE);
        assert!(entries.values().all(|entry| entry.mtime == ENTRY_MTIME));
        assert_eq!(packaged.files, 5);
        assert_eq!(packaged.content_bytes, 13 + 14 + 16 + 14 + 10);
        assert!(packaged.archive_bytes > 0);
    }

    #[test]
    fn spa_sets_not_found_handling() {
        let dir = site();
        let packaged = package_static_dir(dir.path(), "spa-site", NotFoundHandling::Spa).unwrap();
        let entries = read_archive(packaged.path());
        let manifest: serde_json::Value =
            serde_json::from_str(&entries[MANIFEST_NAME].body).unwrap();
        assert_eq!(manifest["runtime"]["not_found_handling"], "spa");
        assert_eq!(packaged.summary(dir.path())["not_found_handling"], "spa");
    }

    #[test]
    fn same_directory_produces_identical_archives() {
        let dir = site();
        let first =
            package_static_dir(dir.path(), "docs-site", NotFoundHandling::NotFound).unwrap();
        let second =
            package_static_dir(dir.path(), "docs-site", NotFoundHandling::NotFound).unwrap();
        assert_eq!(
            fs::read(first.path()).unwrap(),
            fs::read(second.path()).unwrap()
        );
    }

    #[test]
    fn skips_macos_metadata_and_git() {
        let dir = site();
        write(dir.path(), ".DS_Store", "x");
        write(dir.path(), "._index.html", "x");
        write(dir.path(), "assets/._app.js", "x");
        write(dir.path(), ".git/HEAD", "ref");
        write(dir.path(), "__MACOSX/._index.html", "x");
        // In a worktree or submodule, .git is a file rather than a directory.
        write(dir.path(), "vendor/.git", "gitdir: ../.git/modules/vendor");
        write(dir.path(), "vendor/lib.js", "lib");
        let packaged =
            package_static_dir(dir.path(), "docs-site", NotFoundHandling::NotFound).unwrap();
        let entries = read_archive(packaged.path());
        assert!(entries.contains_key("public/vendor/lib.js"));
        assert_eq!(
            packaged.skipped,
            vec![
                ".DS_Store",
                "._index.html",
                ".git",
                "__MACOSX",
                "assets/._app.js",
                "vendor/.git",
            ]
        );
        for skipped in &packaged.skipped {
            let prefix = format!("public/{skipped}");
            assert!(
                entries.keys().all(|name| !name.starts_with(&prefix)),
                "{skipped} was packaged"
            );
        }
    }

    #[test]
    fn skips_secrets_and_dependencies_when_given_a_project_directory() {
        let dir = site();
        write(dir.path(), ".env", "TOKEN=secret");
        write(dir.path(), ".env.local", "TOKEN=secret");
        write(dir.path(), ".envrc", "export TOKEN=secret");
        write(
            dir.path(),
            "node_modules/left-pad/index.js",
            "module.exports = 1",
        );
        write(dir.path(), "assets/node_modules/x.js", "x");
        let packaged =
            package_static_dir(dir.path(), "docs-site", NotFoundHandling::NotFound).unwrap();
        let entries = read_archive(packaged.path());
        assert!(entries
            .keys()
            .all(|name| !name.contains(".env") && !name.contains("node_modules")));
        assert_eq!(
            packaged.skipped,
            vec![
                ".env",
                ".env.local",
                ".envrc",
                "assets/node_modules",
                "node_modules",
            ]
        );
        assert_eq!(packaged.files, 5);
    }

    #[cfg(unix)]
    #[test]
    fn skips_symlinked_dependencies_instead_of_failing() {
        let dir = site();
        let store = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(store.path(), dir.path().join("node_modules")).unwrap();
        let packaged =
            package_static_dir(dir.path(), "docs-site", NotFoundHandling::NotFound).unwrap();
        assert_eq!(packaged.skipped, vec!["node_modules"]);
    }

    #[test]
    fn limits_count_the_manifest_and_public_entries() {
        let dir = Path::new("dist");
        check_archive_limits(dir, MAX_ENTRIES - 2, 0, 200).unwrap();
        let error = check_archive_limits(dir, MAX_ENTRIES - 1, 0, 200)
            .unwrap_err()
            .to_string();
        assert!(error.contains("100001 archive entries"), "{error}");

        check_archive_limits(dir, 10, MAX_TOTAL_BYTES - 200, 200).unwrap();
        let error = check_archive_limits(dir, 10, MAX_TOTAL_BYTES - 199, 200)
            .unwrap_err()
            .to_string();
        assert!(error.contains("accepts at most"), "{error}");
    }

    #[test]
    fn requires_root_index_html() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "dist/index.html", "x");
        let error = package_static_dir(dir.path(), "docs-site", NotFoundHandling::NotFound)
            .unwrap_err()
            .to_string();
        assert!(error.contains("no index.html at its root"), "{error}");
    }

    #[test]
    fn rejects_an_artifact_directory() {
        let dir = site();
        write(dir.path(), MANIFEST_NAME, "{}");
        let error = package_static_dir(dir.path(), "docs-site", NotFoundHandling::NotFound)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("already a Hot Pod artifact directory"),
            "{error}"
        );
    }

    #[test]
    fn rejects_a_file_path() {
        let dir = site();
        let error = package_static_dir(
            &dir.path().join("index.html"),
            "docs-site",
            NotFoundHandling::NotFound,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("must be a directory"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinks() {
        let dir = site();
        std::os::unix::fs::symlink("index.html", dir.path().join("home.html")).unwrap();
        let error = package_static_dir(dir.path(), "docs-site", NotFoundHandling::NotFound)
            .unwrap_err()
            .to_string();
        assert!(error.contains("home.html is a symlink"), "{error}");
    }
}
