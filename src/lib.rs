use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::exceptions::{PyValueError, PyMemoryError, PySystemError};

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce, Key
};
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use getrandom::getrandom;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

const MAX_BUFFER_SIZE: usize = 10 * 1024 * 1024; // 10MB
const AES_KEY_SIZE: usize = 32;
const AES_IV_SIZE: usize = 12;
const AES_TAG_SIZE: usize = 16;

#[pyfunction]
fn aes_gcm_encrypt<'py>(
    py: Python<'py>,
    plaintext: &[u8],
    key: &[u8],
    iv: &[u8],
    aad: Option<&[u8]>,
) -> PyResult<(&'py PyBytes, &'py PyBytes)> {
    if key.len() != AES_KEY_SIZE {
        return Err(PyValueError::new_err("Key must be 32 bytes"));
    }
    if iv.len() != AES_IV_SIZE {
        return Err(PyValueError::new_err("IV must be 12 bytes"));
    }
    if plaintext.len() > MAX_BUFFER_SIZE {
        return Err(PyValueError::new_err("Plaintext exceeds maximum size (10MB)"));
    }

    let key_array: &[u8; AES_KEY_SIZE] = key.try_into()
        .map_err(|_| PyValueError::new_err("Invalid key size"))?;
    let nonce_array: &[u8; AES_IV_SIZE] = iv.try_into()
        .map_err(|_| PyValueError::new_err("Invalid IV size"))?;

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key_array));
    let nonce = Nonce::from_slice(nonce_array);

    let payload = if let Some(aad_data) = aad {
        Payload {
            msg: plaintext,
            aad: aad_data,
        }
    } else {
        Payload {
            msg: plaintext,
            aad: b"",
        }
    };

    let ciphertext = cipher.encrypt(nonce, payload)
        .map_err(|_| PyValueError::new_err("Encryption failed"))?;

    if ciphertext.len() < AES_TAG_SIZE {
        return Err(PyValueError::new_err("Invalid ciphertext length"));
    }

    let tag_start = ciphertext.len() - AES_TAG_SIZE;
    let ct_bytes = PyBytes::new(py, &ciphertext[..tag_start]);
    let tag_bytes = PyBytes::new(py, &ciphertext[tag_start..]);

    Ok((ct_bytes, tag_bytes))
}

#[pyfunction]
fn aes_gcm_decrypt<'py>(
    py: Python<'py>,
    ciphertext: &[u8],
    key: &[u8],
    iv: &[u8],
    tag: &[u8],
    aad: Option<&[u8]>,
) -> PyResult<&'py PyBytes> {
    if key.len() != AES_KEY_SIZE {
        return Err(PyValueError::new_err("Key must be 32 bytes"));
    }
    if iv.len() != AES_IV_SIZE {
        return Err(PyValueError::new_err("IV must be 12 bytes"));
    }
    if tag.len() != AES_TAG_SIZE {
        return Err(PyValueError::new_err("Tag must be 16 bytes"));
    }
    if ciphertext.len() > MAX_BUFFER_SIZE {
        return Err(PyValueError::new_err("Ciphertext exceeds maximum size (10MB)"));
    }

    let key_array: &[u8; AES_KEY_SIZE] = key.try_into()
        .map_err(|_| PyValueError::new_err("Invalid key size"))?;
    let nonce_array: &[u8; AES_IV_SIZE] = iv.try_into()
        .map_err(|_| PyValueError::new_err("Invalid IV size"))?;

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key_array));
    let nonce = Nonce::from_slice(nonce_array);

    let mut combined = Vec::with_capacity(ciphertext.len() + tag.len());
    combined.extend_from_slice(ciphertext);
    combined.extend_from_slice(tag);

    let payload = if let Some(aad_data) = aad {
        Payload {
            msg: &combined,
            aad: aad_data,
        }
    } else {
        Payload {
            msg: &combined,
            aad: b"",
        }
    };

    let mut plaintext = cipher.decrypt(nonce, payload)
        .map_err(|_| PyValueError::new_err("Decryption failed (Authentication Tag Mismatch or corrupted data)"))?;

    let result = PyBytes::new(py, &plaintext);
    plaintext.zeroize();

    Ok(result)
}

#[pyfunction]
fn generate_secure_random<'py>(py: Python<'py>, num_bytes: usize) -> PyResult<&'py PyBytes> {
    if num_bytes == 0 || num_bytes > MAX_BUFFER_SIZE {
        return Err(PyValueError::new_err(format!(
            "Invalid buffer size: {}. Must be between 1 and {} bytes",
            num_bytes, MAX_BUFFER_SIZE
        )));
    }

    let mut buffer = vec![0u8; num_bytes];
    getrandom(&mut buffer)
        .map_err(|_| PySystemError::new_err("CSPRNG failed (getrandom error)"))?;

    let result = PyBytes::new(py, &buffer);
    buffer.zeroize();

    Ok(result)
}

#[pyfunction]
fn sha256_hash<'py>(py: Python<'py>, data: &[u8]) -> PyResult<&'py PyBytes> {
    if data.len() > MAX_BUFFER_SIZE {
        return Err(PyValueError::new_err("Data exceeds maximum size (10MB)"));
    }

    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();

    Ok(PyBytes::new(py, hash.as_slice()))
}

#[pyfunction]
fn compare_digest(a: &[u8], b: &[u8]) -> PyResult<bool> {
    if a.len() != b.len() {
        return Ok(false);
    }

    Ok(a.ct_eq(b).into())
}

#[pyfunction]
fn x25519_generate_keypair<'py>(py: Python<'py>) -> PyResult<(&'py PyBytes, &'py PyBytes)> {
    let mut secret_bytes = [0u8; 32];
    getrandom(&mut secret_bytes)
        .map_err(|_| PySystemError::new_err("CSPRNG failed"))?;

    let secret = EphemeralSecret::from(secret_bytes);
    let public = X25519PublicKey::from(&secret);

    let secret_result = PyBytes::new(py, &secret_bytes);
    let public_result = PyBytes::new(py, public.as_bytes());

    secret_bytes.zeroize();

    Ok((secret_result, public_result))
}

#[pyfunction]
fn x25519_diffie_hellman<'py>(
    py: Python<'py>,
    secret_key: &[u8],
    public_key: &[u8],
) -> PyResult<&'py PyBytes> {
    if secret_key.len() != 32 {
        return Err(PyValueError::new_err("Secret key must be 32 bytes"));
    }
    if public_key.len() != 32 {
        return Err(PyValueError::new_err("Public key must be 32 bytes"));
    }

    let secret_array: [u8; 32] = secret_key.try_into()
        .map_err(|_| PyValueError::new_err("Invalid secret key"))?;
    let public_array: [u8; 32] = public_key.try_into()
        .map_err(|_| PyValueError::new_err("Invalid public key"))?;

    let secret = EphemeralSecret::from(secret_array);
    let public = X25519PublicKey::from(public_array);
    let shared = secret.diffie_hellman(&public);

    Ok(PyBytes::new(py, shared.as_bytes()))
}

#[pyfunction]
fn ed25519_generate_keypair<'py>(py: Python<'py>) -> PyResult<(&'py PyBytes, &'py PyBytes)> {
    let mut secret_bytes = [0u8; 32];
    getrandom(&mut secret_bytes)
        .map_err(|_| PySystemError::new_err("CSPRNG failed"))?;

    let signing_key = SigningKey::from_bytes(&secret_bytes);
    let verifying_key = signing_key.verifying_key();

    let secret_result = PyBytes::new(py, &secret_bytes);
    let public_result = PyBytes::new(py, verifying_key.as_bytes());

    secret_bytes.zeroize();

    Ok((secret_result, public_result))
}

#[pyfunction]
fn ed25519_sign<'py>(
    py: Python<'py>,
    secret_key: &[u8],
    message: &[u8],
) -> PyResult<&'py PyBytes> {
    if secret_key.len() != 32 {
        return Err(PyValueError::new_err("Secret key must be 32 bytes"));
    }

    let secret_array: [u8; 32] = secret_key.try_into()
        .map_err(|_| PyValueError::new_err("Invalid secret key"))?;

    let signing_key = SigningKey::from_bytes(&secret_array);
    let signature = signing_key.sign(message);

    Ok(PyBytes::new(py, &signature.to_bytes()))
}

#[pyfunction]
fn ed25519_verify(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> PyResult<bool> {
    if public_key.len() != 32 {
        return Err(PyValueError::new_err("Public key must be 32 bytes"));
    }
    if signature.len() != 64 {
        return Err(PyValueError::new_err("Signature must be 64 bytes"));
    }

    let public_array: [u8; 32] = public_key.try_into()
        .map_err(|_| PyValueError::new_err("Invalid public key"))?;
    let sig_array: [u8; 64] = signature.try_into()
        .map_err(|_| PyValueError::new_err("Invalid signature"))?;

    let verifying_key = VerifyingKey::from_bytes(&public_array)
        .map_err(|_| PyValueError::new_err("Invalid public key format"))?;
    let sig = Signature::from_bytes(&sig_array);

    Ok(verifying_key.verify(message, &sig).is_ok())
}

#[pyfunction]
fn hmac_sha256<'py>(
    py: Python<'py>,
    key: &[u8],
    message: &[u8],
) -> PyResult<&'py PyBytes> {
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_| PyValueError::new_err("Invalid HMAC key length"))?;
    mac.update(message);
    let result = mac.finalize();

    Ok(PyBytes::new(py, &result.into_bytes()))
}

#[pyfunction]
fn pbkdf2_derive_key<'py>(
    py: Python<'py>,
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    output_len: usize,
) -> PyResult<&'py PyBytes> {
    if iterations == 0 {
        return Err(PyValueError::new_err("Iterations must be > 0"));
    }
    if output_len == 0 || output_len > MAX_BUFFER_SIZE {
        return Err(PyValueError::new_err("Invalid output length"));
    }

    let mut output = vec![0u8; output_len];
    pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut output);

    let result = PyBytes::new(py, &output);
    output.zeroize();

    Ok(result)
}

#[pyfunction]
fn benchmark() -> PyResult<()> {
    Ok(())
}

#[pymodule]
fn crypto_accelerator(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(aes_gcm_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(aes_gcm_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(generate_secure_random, m)?)?;
    m.add_function(wrap_pyfunction!(sha256_hash, m)?)?;
    m.add_function(wrap_pyfunction!(compare_digest, m)?)?;
    m.add_function(wrap_pyfunction!(x25519_generate_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(x25519_diffie_hellman, m)?)?;
    m.add_function(wrap_pyfunction!(ed25519_generate_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(ed25519_sign, m)?)?;
    m.add_function(wrap_pyfunction!(ed25519_verify, m)?)?;
    m.add_function(wrap_pyfunction!(hmac_sha256, m)?)?;
    m.add_function(wrap_pyfunction!(pbkdf2_derive_key, m)?)?;
    m.add_function(wrap_pyfunction!(benchmark, m)?)?;
    Ok(())
}
