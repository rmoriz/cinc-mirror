//! FTP download into the content-addressed store.
//!
//! Task 7 leaves a verified `.part` file; this test proves the two layers fit
//! together: a real FTP transfer through the payload ladder, then a commit whose
//! blob is named by — and verifies against — its SHA-256.

mod support;

use cinc_mirror::config::TransportKind;
use cinc_mirror::hash::{hash_file, hash_reader, ExpectedHashes};
use cinc_mirror::source::{Source, SourceConfig};
use cinc_mirror::store::Store;
use url::Url;

const REMOTE: &str = "stable/cinc/19.4.46/debian/13/cinc_19.4.46-1_amd64.deb";

#[tokio::test]
async fn ftp_roundtrip_matches_hash() {
    let body: Vec<u8> = (0..96 * 1024 + 23)
        .map(|index| (index % 251) as u8)
        .collect();

    let root = tempfile::tempdir().expect("ftp root");
    let remote = root.path().join("pub/cinc/files").join(REMOTE);
    std::fs::create_dir_all(remote.parent().expect("remote parent")).expect("fixture dir");
    std::fs::write(&remote, &body).expect("package fixture");

    let server = support::start_ftp(root.path().to_path_buf()).await;

    let config = SourceConfig {
        https_base: Url::parse("https://downloads.cinc.sh/files").expect("base url"),
        ftp_host: "127.0.0.1".to_string(),
        ftp_port: server.port,
        ftp_base_path: "pub/cinc/files".to_string(),
        transports: vec![TransportKind::Ftp],
    };
    let source = Source::new(&config).expect("source");

    let state = tempfile::tempdir().expect("state dir");
    let store = Store::open(state.path()).expect("store");

    let digest = hash_reader(&body[..]).expect("hash fixture").sha256;
    let expected = ExpectedHashes {
        sha256: digest.clone(),
        sha512: None,
        sha1: None,
        md5: None,
        size: Some(body.len() as u64),
    };

    let partial = store.partial_path(&digest).expect("partial path");
    let outcome = source
        .download(REMOTE, &partial, &expected)
        .await
        .expect("ftp download");

    assert_eq!(outcome.transport, TransportKind::Ftp);
    assert_eq!(outcome.resumed_from, 0);
    assert_eq!(outcome.hashes.sha256, digest);
    assert!(
        partial.is_file(),
        "the verified download waits in the partial directory"
    );
    assert!(
        !store.has(&digest),
        "a verified partial is not yet a committed blob"
    );

    let committed = store.commit(&digest, &partial).expect("commit");

    assert_eq!(committed, store.path(&digest).expect("blob path"));
    assert_eq!(std::fs::read(&committed).expect("blob"), body);
    assert_eq!(
        hash_file(&committed).expect("hash blob").sha256,
        digest,
        "the committed bytes hash to the file name"
    );
    assert!(store.verify(&digest).expect("verify blob"));
    assert!(!partial.exists(), "commit removes the partial");
}
