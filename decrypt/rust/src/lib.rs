//! SecretCrypto - Descifra los valores generados con SecretEncryptor (Rust).
//!
//! Formato del valor:
//!   con prefijo:  "<algoritmo>:<Base64>"  -> secret_crypto::decrypt(valor, llave, None)
//!   sin prefijo:  "<Base64>"              -> secret_crypto::decrypt(valor, llave, Some("aes256gcm"))
//!
//! Algoritmos: aes256gcm, chacha20poly1305, aes256cbc-hmac, aes128gcm,
//! aes256cbc, 3des, base64 (sin llave).

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};
use base64::{engine::general_purpose::STANDARD, Engine};
use chacha20poly1305::ChaCha20Poly1305;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
type TdesCbcDec = cbc::Decryptor<des::TdesEde3>;

const DECRYPT_ERROR: &str = "No se pudo descifrar: la llave o el algoritmo no corresponden";

/// Descifra un valor. Si trae prefijo, el algoritmo es opcional; si se indican ambos, deben coincidir.
pub fn decrypt(value: &str, master_key_base64: &str, algorithm: Option<&str>) -> Result<String, String> {
    let v = value.trim();
    let mut body = v;
    let mut algorithm = algorithm.map(str::to_string);
    if let Some(sep) = v.find(':').filter(|&i| i > 0) {
        let prefix = &v[..sep];
        if let Some(alg) = &algorithm {
            if alg != prefix {
                return Err(format!("El prefijo ({prefix}) no coincide con el algoritmo indicado ({alg})"));
            }
        }
        algorithm = Some(prefix.to_string());
        body = &v[sep + 1..];
    }
    let algorithm = algorithm.ok_or("El valor no tiene prefijo: indica el algoritmo")?;

    let payload = STANDARD.decode(body).map_err(|e| format!("Base64 inválido: {e}"))?;
    if algorithm == "base64" {
        return String::from_utf8(payload).map_err(|e| e.to_string());
    }

    let mk = parse_master_key(master_key_base64)?;
    let data = match algorithm.as_str() {
        "aes256gcm" => {
            let (nonce, ct) = split_aead(&payload)?;
            Aes256Gcm::new_from_slice(&derive_key(&mk, "aes256gcm"))
                .map_err(|e| e.to_string())?
                .decrypt(Nonce::from_slice(nonce), ct)
                .map_err(|_| DECRYPT_ERROR.to_string())?
        }
        "chacha20poly1305" => {
            let (nonce, ct) = split_aead(&payload)?;
            ChaCha20Poly1305::new_from_slice(&derive_key(&mk, "chacha20"))
                .map_err(|e| e.to_string())?
                .decrypt(chacha20poly1305::Nonce::from_slice(nonce), ct)
                .map_err(|_| DECRYPT_ERROR.to_string())?
        }
        "aes128gcm" => {
            let (nonce, ct) = split_aead(&payload)?;
            Aes128Gcm::new_from_slice(&derive_key(&mk, "aes128gcm")[..16])
                .map_err(|e| e.to_string())?
                .decrypt(Nonce::from_slice(nonce), ct)
                .map_err(|_| DECRYPT_ERROR.to_string())?
        }
        "aes256cbc-hmac" => {
            if payload.len() < 32 + 16 {
                return Err("Valor cifrado demasiado corto".into());
            }
            let (ivct, tag) = payload.split_at(payload.len() - 32);
            let mut mac = <HmacSha256 as Mac>::new_from_slice(&derive_key(&mk, "mac")).map_err(|e| e.to_string())?;
            mac.update(ivct);
            mac.verify_slice(tag).map_err(|_| "Integridad no válida".to_string())?;
            let (iv, ct) = ivct.split_at(16);
            Aes256CbcDec::new_from_slices(&derive_key(&mk, "enc"), iv)
                .map_err(|e| e.to_string())?
                .decrypt_padded_vec_mut::<Pkcs7>(ct)
                .map_err(|_| DECRYPT_ERROR.to_string())?
        }
        "aes256cbc" => {
            if payload.len() < 32 {
                return Err("Valor cifrado demasiado corto".into());
            }
            let (iv, ct) = payload.split_at(16);
            Aes256CbcDec::new_from_slices(&derive_key(&mk, "aes256cbc"), iv)
                .map_err(|e| e.to_string())?
                .decrypt_padded_vec_mut::<Pkcs7>(ct)
                .map_err(|_| DECRYPT_ERROR.to_string())?
        }
        "3des" => {
            if payload.len() < 16 {
                return Err("Valor cifrado demasiado corto".into());
            }
            let (iv, ct) = payload.split_at(8);
            TdesCbcDec::new_from_slices(&derive_key(&mk, "3des")[..24], iv)
                .map_err(|e| e.to_string())?
                .decrypt_padded_vec_mut::<Pkcs7>(ct)
                .map_err(|_| DECRYPT_ERROR.to_string())?
        }
        other => return Err(format!("Algoritmo no soportado: {other}")),
    };
    String::from_utf8(data).map_err(|e| e.to_string())
}

fn derive_key(master_key: &[u8], label: &str) -> Vec<u8> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(master_key).expect("HMAC acepta cualquier largo de llave");
    mac.update(label.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

fn parse_master_key(master_key_base64: &str) -> Result<Vec<u8>, String> {
    match STANDARD.decode(master_key_base64.trim()) {
        Ok(key) if key.len() == 32 => Ok(key),
        _ => Err("Llave maestra inválida: debe tener 32 bytes en Base64".into()),
    }
}

fn split_aead(payload: &[u8]) -> Result<(&[u8], &[u8]), String> {
    if payload.len() < 12 + 16 {
        return Err("Valor cifrado demasiado corto".into());
    }
    Ok(payload.split_at(12))
}
