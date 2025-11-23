#[cfg(feature = "python")]
use pyo3::prelude::*;
#[cfg(feature = "python")]
use pyo3::exceptions::PyValueError;

pub mod cbc256;
pub mod ctr256;
pub mod ige256;

pub use cbc256::{cbc256_encrypt, cbc256_decrypt};
pub use ctr256::{ctr256_encrypt, ctr256_decrypt};
pub use ige256::{ige256_encrypt, ige256_decrypt};

#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(name = "ige256_encrypt")]
fn py_ige256_encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> PyResult<Vec<u8>> {
    if data.is_empty() {
        return Err(PyValueError::new_err("Data must not be empty"));
    }
    if data.len() % 16 != 0 {
        return Err(PyValueError::new_err("Data size must match a multiple of 16 bytes"));
    }
    if key.len() != 32 {
        return Err(PyValueError::new_err("Key size must be exactly 32 bytes"));
    }
    if iv.len() != 32 {
        return Err(PyValueError::new_err("IV size must be exactly 32 bytes"));
    }
    Ok(ige256_encrypt(data, key, iv))
}

#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(name = "ige256_decrypt")]
fn py_ige256_decrypt(data: &[u8], key: &[u8], iv: &[u8]) -> PyResult<Vec<u8>> {
    if data.is_empty() {
        return Err(PyValueError::new_err("Data must not be empty"));
    }
    if data.len() % 16 != 0 {
        return Err(PyValueError::new_err("Data size must match a multiple of 16 bytes"));
    }
    if key.len() != 32 {
        return Err(PyValueError::new_err("Key size must be exactly 32 bytes"));
    }
    if iv.len() != 32 {
        return Err(PyValueError::new_err("IV size must be exactly 32 bytes"));
    }
    Ok(ige256_decrypt(data, key, iv))
}

#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(name = "ctr256_encrypt")]
fn py_ctr256_encrypt(data: &[u8], key: &[u8], iv: &[u8], state: &[u8]) -> PyResult<Vec<u8>> {
    if data.is_empty() {
        return Err(PyValueError::new_err("Data must not be empty"));
    }
    if key.len() != 32 {
        return Err(PyValueError::new_err("Key size must be exactly 32 bytes"));
    }
    if iv.len() != 16 {
        return Err(PyValueError::new_err("IV size must be exactly 16 bytes"));
    }
    if state.len() != 1 {
         return Err(PyValueError::new_err("State size must be exactly 1 byte"));
    }
    Ok(ctr256_encrypt(data, key, iv, state[0]))
}

#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(name = "ctr256_decrypt")]
fn py_ctr256_decrypt(data: &[u8], key: &[u8], iv: &[u8], state: &[u8]) -> PyResult<Vec<u8>> {
    if data.is_empty() {
        return Err(PyValueError::new_err("Data must not be empty"));
    }
    if key.len() != 32 {
        return Err(PyValueError::new_err("Key size must be exactly 32 bytes"));
    }
    if iv.len() != 16 {
        return Err(PyValueError::new_err("IV size must be exactly 16 bytes"));
    }
    if state.len() != 1 {
         return Err(PyValueError::new_err("State size must be exactly 1 byte"));
    }
    Ok(ctr256_decrypt(data, key, iv, state[0]))
}

#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(name = "cbc256_encrypt")]
fn py_cbc256_encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> PyResult<Vec<u8>> {
    if data.is_empty() {
        return Err(PyValueError::new_err("Data must not be empty"));
    }
    if data.len() % 16 != 0 {
        return Err(PyValueError::new_err("Data size must match a multiple of 16 bytes"));
    }
    if key.len() != 32 {
        return Err(PyValueError::new_err("Key size must be exactly 32 bytes"));
    }
    if iv.len() != 16 {
        return Err(PyValueError::new_err("IV size must be exactly 16 bytes"));
    }
    Ok(cbc256_encrypt(data, key, iv))
}

#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(name = "cbc256_decrypt")]
fn py_cbc256_decrypt(data: &[u8], key: &[u8], iv: &[u8]) -> PyResult<Vec<u8>> {
    if data.is_empty() {
        return Err(PyValueError::new_err("Data must not be empty"));
    }
    if data.len() % 16 != 0 {
        return Err(PyValueError::new_err("Data size must match a multiple of 16 bytes"));
    }
    if key.len() != 32 {
        return Err(PyValueError::new_err("Key size must be exactly 32 bytes"));
    }
    if iv.len() != 16 {
        return Err(PyValueError::new_err("IV size must be exactly 16 bytes"));
    }
    Ok(cbc256_decrypt(data, key, iv))
}

#[cfg(feature = "python")]
#[pymodule]
fn tezcrypto(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(py_ige256_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(py_ige256_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(py_ctr256_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(py_ctr256_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(py_cbc256_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(py_cbc256_decrypt, m)?)?;
    Ok(())
}
