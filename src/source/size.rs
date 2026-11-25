//! Advisory artifact sizes.
//!
//! Upstream metadata carries no size, so a plan resolves sizes through a
//! three-rung ladder, cheapest first:
//!
//! 1. one FTP control connection per directory and `MLSD`, whose
//!    `type=file;size=N;` records answer every file at once;
//! 2. if `MLSD` is unsupported, `SIZE` for every `*.metadata.json` sibling
//!    basename on the same connection;
//! 3. if FTP is unreachable, `HEAD` each package URL and read
//!    `Content-Length`.
//!
//! Failures on the last rung drop that file from the map rather than failing a
//! plan: sizes are advisory, and the plan still reports its totals from what
//! could be resolved. A directory listing failure is different — it means the
//! crawl itself is no longer trustworthy — and is returned.

use std::collections::HashMap;
use std::time::Duration;

use crate::source::{ensure_https, join_path, Source, SourceError};

/// Budget for one FTP control operation.
const FTP_TIMEOUT: Duration = Duration::from_secs(20);

/// The suffix that marks a metadata document beside a package.
const METADATA_SUFFIX: &str = ".metadata.json";

impl Source {
    /// Resolve the size of every file in `dir`, keyed by basename.
    ///
    /// `dir` is relative to the upstream root, e.g.
    /// `stable/cinc/19.4.46/debian/13`.
    ///
    /// # Errors
    ///
    /// Returns [`SourceError::Config`] when `dir` contains a traversal segment,
    /// and the listing error when the HTTPS directory listing needed by a
    /// fallback fails. Individual `SIZE` or `HEAD` failures only omit that file.
    pub async fn sizes(&self, dir: &str) -> Result<HashMap<String, u64>, SourceError> {
        let ftp_path = join_ftp_path(&self.ftp_base_path, dir)?;

        match self.ftp_sizes(dir, &ftp_path).await? {
            Some(sizes) => Ok(sizes),
            None => {
                let names = self.package_basenames(dir).await?;
                Ok(self.head_sizes(dir, &names).await)
            }
        }
    }

    /// Try `MLSD`, then `SIZE`, over one control connection.
    ///
    /// `Ok(None)` means FTP could not answer and the caller should fall back to
    /// HTTPS. `Err` is reserved for a listing failure during the `SIZE`
    /// fallback.
    async fn ftp_sizes(
        &self,
        dir: &str,
        ftp_path: &str,
    ) -> Result<Option<HashMap<String, u64>>, SourceError> {
        let Ok(Ok(mut stream)) = tokio::time::timeout(FTP_TIMEOUT, self.ftp_connect()).await else {
            return Ok(None);
        };

        if let Ok(Ok(lines)) = tokio::time::timeout(FTP_TIMEOUT, stream.mlsd(Some(ftp_path))).await
        {
            let sizes = parse_mlsd(&lines);
            let _ = tokio::time::timeout(FTP_TIMEOUT, stream.quit()).await;
            return Ok(Some(sizes));
        }

        // MLSD unsupported or refused: SIZE needs the names, so list the
        // directory over HTTPS and ask for each package sibling.
        let names = self.package_basenames(dir).await?;
        let mut sizes = HashMap::new();
        for name in &names {
            let remote = join_ftp_segments([ftp_path, name]);
            if let Ok(Ok(size)) = tokio::time::timeout(FTP_TIMEOUT, stream.size(&remote)).await {
                sizes.insert(name.clone(), u64::try_from(size).unwrap_or(u64::MAX));
            }
        }
        let _ = tokio::time::timeout(FTP_TIMEOUT, stream.quit()).await;

        if sizes.is_empty() {
            Ok(None)
        } else {
            Ok(Some(sizes))
        }
    }

    /// Open and log in to the FTP host anonymously.
    async fn ftp_connect(&self) -> Result<suppaftp::tokio::AsyncFtpStream, suppaftp::FtpError> {
        let mut stream =
            suppaftp::tokio::AsyncFtpStream::connect((self.ftp_host.as_str(), self.ftp_port))
                .await?;
        stream.login("anonymous", "anonymous").await?;
        Ok(stream)
    }

    /// Package basenames in `dir`, derived from the `*.metadata.json` siblings.
    async fn package_basenames(&self, dir: &str) -> Result<Vec<String>, SourceError> {
        let entries = self.list(dir).await?;
        let mut names: Vec<String> = entries
            .into_iter()
            .filter(|entry| !entry.is_dir)
            .filter_map(|entry| entry.name.strip_suffix(METADATA_SUFFIX).map(str::to_string))
            .collect();
        names.sort();
        names.dedup();
        Ok(names)
    }

    /// Resolve sizes with one HTTPS `HEAD` per package.
    async fn head_sizes(&self, dir: &str, names: &[String]) -> HashMap<String, u64> {
        let mut sizes = HashMap::new();
        for name in names {
            let path = join_ftp_segments([dir, name]);
            let Ok(url) = join_path(&self.https_base, &path, false).and_then(ensure_https) else {
                continue;
            };
            // Advisory: a refused or unlabelled HEAD means "unknown".
            if let Ok(Some(size)) = self.fetcher.head_len(&url).await {
                sizes.insert(name.clone(), size);
            }
        }
        sizes
    }
}

/// Parse the `MLSD` records of one directory.
///
/// Each record is `fact=value;fact=value; name`. Directories, records without a
/// parsable `size`, and unparsable lines are dropped. The name keeps embedded
/// spaces and is the map key, so two records for one name keep the last size.
#[must_use]
pub fn parse_mlsd(lines: &[String]) -> HashMap<String, u64> {
    let mut sizes = HashMap::new();
    for line in lines {
        if let Some((name, size)) = parse_mlsd_line(line) {
            sizes.insert(name, size);
        }
    }
    sizes
}

fn parse_mlsd_line(line: &str) -> Option<(String, u64)> {
    let (facts, name) = line.split_once(' ')?;
    let name = name.trim_end_matches(['\r', '\n']).trim_start();
    if name.is_empty() {
        return None;
    }

    let mut is_file = false;
    let mut size = None;
    for fact in facts.split(';') {
        let Some((key, value)) = fact.split_once('=') else {
            continue;
        };
        if key.trim().eq_ignore_ascii_case("type") {
            is_file = value.trim().eq_ignore_ascii_case("file");
        } else if key.trim().eq_ignore_ascii_case("size") {
            size = value.trim().parse::<u64>().ok();
        }
    }

    if !is_file {
        return None;
    }
    size.map(|size| (name.to_string(), size))
}

/// Join FTP path segments, refusing traversal.
fn join_ftp_path(base: &str, dir: &str) -> Result<String, SourceError> {
    let mut segments = Vec::new();
    for segment in base.split('/').chain(dir.split('/')) {
        let segment = segment.trim();
        if segment.is_empty() {
            continue;
        }
        if segment == "." || segment == ".." {
            return Err(SourceError::Config {
                reason: format!("path `{dir}` must not contain traversal segments"),
            });
        }
        segments.push(segment);
    }

    if segments.is_empty() {
        return Err(SourceError::Config {
            reason: "FTP base path and directory must not both be empty".to_string(),
        });
    }

    Ok(segments.join("/"))
}

/// Join already-validated path segments with `/`.
fn join_ftp_segments<const N: usize>(parts: [&str; N]) -> String {
    parts
        .iter()
        .map(|part| part.trim_matches('/'))
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_ftp_traversal() {
        assert!(join_ftp_path("pub/cinc/files", "stable/cinc").is_ok());
        assert!(join_ftp_path("pub/cinc/files", "../../etc").is_err());
        assert!(join_ftp_path("", "").is_err());
    }

    #[test]
    fn joins_ftp_segments_without_doubled_slashes() {
        assert_eq!(
            join_ftp_segments(["pub/cinc/files/", "/stable/cinc/"]),
            "pub/cinc/files/stable/cinc"
        );
    }
}
