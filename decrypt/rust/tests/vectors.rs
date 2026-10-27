use secret_crypto::decrypt;
use std::collections::HashMap;

const ALGORITHMS: [&str; 7] = ["aes256gcm", "chacha20poly1305", "aes256cbc-hmac", "aes128gcm", "aes256cbc", "3des", "base64"];

fn load_vectors() -> HashMap<String, String> {
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../test-vectors.txt")).unwrap();
    text.lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

#[test]
fn test_vectors() {
    let vec = load_vectors();
    let (key, plain) = (&vec["masterKey"], &vec["plainText"]);
    for alg in ALGORITHMS {
        assert_eq!(&decrypt(&vec[alg], key, None).unwrap(), plain, "{alg}");
        assert_eq!(&decrypt(&vec[&format!("{alg}.raw")], key, Some(alg)).unwrap(), plain, "{alg}.raw");
    }
    assert!(decrypt(&vec["tampered"], key, None).is_err());
    assert!(decrypt(&vec["aes256gcm"], key, Some("aes128gcm")).is_err());
}
