use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use rand::{Rng, RngCore};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

pub fn digest(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

pub fn secret() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn code() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut generator = rand::thread_rng();
    let letters: String = (0..12)
        .map(|_| ALPHABET[generator.gen_range(0..ALPHABET.len())] as char)
        .collect();
    format!("{}-{}-{}", &letters[..4], &letters[4..8], &letters[8..])
}

pub fn code_hash(value: &str) -> String {
    digest(&value.replace('-', "").trim().to_uppercase())
}

pub fn same(left: &str, right: &str) -> bool {
    left.as_bytes().ct_eq(right.as_bytes()).into()
}

pub fn valid_name(name: &str) -> bool {
    (3..=16).contains(&name.len())
        && name
            .bytes()
            .all(|letter| letter.is_ascii_alphanumeric() || letter == b'_')
}

pub fn valid_request_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|letter| letter.is_ascii_digit() || (b'a'..=b'f').contains(&letter))
}

/// Match Python's HMAC derivation so already issued retry grants survive migration.
pub fn derive_token(seed: &str, request_id: &str, nonce: &str, kind: &str) -> String {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(seed.as_bytes()).expect("HMAC accepts any key length");
    mac.update(format!("{request_id}:{nonce}:{kind}").as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_derivation_matches_the_persisted_fixture() {
        assert_eq!(
            derive_token("poll", &"a".repeat(64), "nonce", "game"),
            "82d090d781a3e9ce0f7a9b92086477d92d92dfa377721e76fd7b0dd171e05251"
        );
        assert_ne!(
            derive_token("poll", &"a".repeat(64), "nonce", "game"),
            derive_token("poll", &"a".repeat(64), "nonce", "refresh")
        );
    }

    #[test]
    fn codes_names_and_retry_identifiers_have_distinct_rules() {
        assert_eq!(code_hash(" aaaa-bbbb-cccc "), digest("AAAABBBBCCCC"));
        assert!(valid_name("Alice_13"));
        assert!(!valid_name("名字"));
        assert!(!valid_name("ab"));
        assert!(!valid_name("Alice Smith"));
        assert!(valid_request_id(&"a".repeat(64)));
        assert!(!valid_request_id(&"A".repeat(64)));
        assert!(same("token", "token"));
        assert!(!same("token", "token-other"));
        let generated = code();
        assert_eq!(generated.len(), 14);
        assert!(generated.split('-').all(|part| part.len() == 4));
    }
}
