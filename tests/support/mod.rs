//! Shared test fixtures.
//!
//! `libunftp` ships no storage backend of its own, so the FTP tests bring a
//! small read-only one over a temporary directory. Read-only is enough: size
//! resolution only reads metadata.

use std::fmt;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::time::SystemTime;

use async_trait::async_trait;
use libunftp::auth::DefaultUser;
use libunftp::storage::{Error, ErrorKind, Fileinfo, Metadata, Result, StorageBackend};

/// Metadata for one file below the test root.
#[derive(Debug, Clone)]
pub struct FsMetadata {
    len: u64,
    is_dir: bool,
    modified: SystemTime,
}

impl From<std::fs::Metadata> for FsMetadata {
    fn from(metadata: std::fs::Metadata) -> Self {
        Self {
            len: metadata.len(),
            is_dir: metadata.is_dir(),
            modified: metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH),
        }
    }
}

impl Metadata for FsMetadata {
    fn len(&self) -> u64 {
        self.len
    }

    fn is_dir(&self) -> bool {
        self.is_dir
    }

    fn is_file(&self) -> bool {
        !self.is_dir
    }

    fn is_symlink(&self) -> bool {
        false
    }

    fn modified(&self) -> Result<SystemTime> {
        Ok(self.modified)
    }

    fn gid(&self) -> u32 {
        0
    }

    fn uid(&self) -> u32 {
        0
    }
}

/// A read-only filesystem backend rooted at a temporary directory.
#[derive(Debug, Clone)]
pub struct ReadOnlyFs {
    root: PathBuf,
}

impl ReadOnlyFs {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Resolve a virtual FTP path against the root, ignoring `RootDir` and
    /// refusing to climb out with `..`.
    fn full(&self, path: &Path) -> PathBuf {
        let mut full = self.root.clone();
        for component in path.components() {
            match component {
                Component::Normal(part) => full.push(part),
                Component::ParentDir => {}
                Component::CurDir | Component::RootDir | Component::Prefix(_) => {}
            }
        }
        full
    }
}

fn read_only() -> Error {
    Error::new(
        ErrorKind::PermissionDenied,
        io::Error::new(io::ErrorKind::PermissionDenied, "read-only test backend"),
    )
}

#[async_trait]
impl StorageBackend<DefaultUser> for ReadOnlyFs {
    type Metadata = FsMetadata;

    async fn metadata<P: AsRef<Path> + Send + fmt::Debug>(
        &self,
        _user: &DefaultUser,
        path: P,
    ) -> Result<Self::Metadata> {
        std::fs::metadata(self.full(path.as_ref()))
            .map(FsMetadata::from)
            .map_err(Error::from)
    }

    async fn list<P: AsRef<Path> + Send + fmt::Debug>(
        &self,
        _user: &DefaultUser,
        path: P,
    ) -> Result<Vec<Fileinfo<PathBuf, Self::Metadata>>> {
        let mut entries = Vec::new();
        for entry in std::fs::read_dir(self.full(path.as_ref())).map_err(Error::from)? {
            let entry = entry.map_err(Error::from)?;
            let metadata = entry.metadata().map_err(Error::from)?;
            entries.push(Fileinfo {
                path: entry.path(),
                metadata: FsMetadata::from(metadata),
            });
        }
        Ok(entries)
    }

    async fn get<P: AsRef<Path> + Send + fmt::Debug>(
        &self,
        _user: &DefaultUser,
        path: P,
        start_pos: u64,
    ) -> Result<Box<dyn tokio::io::AsyncRead + Send + Sync + Unpin>> {
        use tokio::io::AsyncSeekExt;

        let mut file = tokio::fs::File::open(self.full(path.as_ref()))
            .await
            .map_err(Error::from)?;
        if start_pos > 0 {
            file.seek(io::SeekFrom::Start(start_pos))
                .await
                .map_err(Error::from)?;
        }
        Ok(Box::new(file))
    }

    async fn put<
        P: AsRef<Path> + Send + fmt::Debug,
        R: tokio::io::AsyncRead + Send + Sync + Unpin + 'static,
    >(
        &self,
        _user: &DefaultUser,
        _input: R,
        _path: P,
        _start_pos: u64,
    ) -> Result<u64> {
        Err(read_only())
    }

    async fn del<P: AsRef<Path> + Send + fmt::Debug>(
        &self,
        _user: &DefaultUser,
        _path: P,
    ) -> Result<()> {
        Err(read_only())
    }

    async fn mkd<P: AsRef<Path> + Send + fmt::Debug>(
        &self,
        _user: &DefaultUser,
        _path: P,
    ) -> Result<()> {
        Err(read_only())
    }

    async fn rename<P: AsRef<Path> + Send + fmt::Debug>(
        &self,
        _user: &DefaultUser,
        _from: P,
        _to: P,
    ) -> Result<()> {
        Err(read_only())
    }

    async fn rmd<P: AsRef<Path> + Send + fmt::Debug>(
        &self,
        _user: &DefaultUser,
        _path: P,
    ) -> Result<()> {
        Err(read_only())
    }

    async fn cwd<P: AsRef<Path> + Send + fmt::Debug>(
        &self,
        _user: &DefaultUser,
        _path: P,
    ) -> Result<()> {
        Err(read_only())
    }
}

/// A running anonymous FTP server over a temporary directory.
pub struct FtpServer {
    pub port: u16,
    handle: tokio::task::JoinHandle<()>,
}

impl Drop for FtpServer {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind a free port")
        .local_addr()
        .expect("local address")
        .port()
}

/// Start a libunftp server serving `root` on a loopback-only free port.
pub async fn start_ftp(root: impl Into<PathBuf>) -> FtpServer {
    let port = free_port();
    let root = root.into();
    let server = libunftp::ServerBuilder::<ReadOnlyFs, DefaultUser>::new(Box::new(move || {
        ReadOnlyFs::new(root.clone())
    }))
    .build()
    .expect("build ftp server");

    let address = format!("127.0.0.1:{port}");
    let handle = tokio::spawn(async move {
        let _ = server.listen(address).await;
    });

    for _ in 0..100 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return FtpServer { port, handle };
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    panic!("ftp server did not start listening on port {port}");
}
