use pyo3::prelude::*;
use scrypt::{scrypt, Params};
use std::time::Instant;

#[pyfunction]
fn estimate_crack_time(
    scrypt_n: u32,
    scrypt_r: u32,
    scrypt_p: u32,
    gpu_cores: u32,
    gpu_clock_ghz: f64,
    dict_size: u64,
) -> f64 {
    // Theoretical time per hash (seconds)
    let operations_per_hash = (2 * scrypt_n * scrypt_r * scrypt_p) as f64;
    let gpu_ops_per_sec = gpu_cores as f64 * gpu_clock_ghz * 1e9;
    let seconds_per_hash = operations_per_hash / gpu_ops_per_sec;

    // Total time (seconds)
    dict_size as f64 * seconds_per_hash
}

#[pyfunction]
fn derive_scrypt_key(
    password: &str,
    salt: &[u8],
    n: u32,
    r: u32,
    p: u32,
    dklen: usize,
) -> PyResult<Vec<u8>> {
    let params = Params::new(n, r, p, dklen).map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
    let mut output = vec![0u8; dklen];
    let start = Instant::now();
    scrypt(password.as_bytes(), salt, &params, &mut output).map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
    let duration = start.elapsed();
    println!("Derived key in {:?}", duration);
    Ok(output)
}

#[pymodule]
fn trycrypt_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(estimate_crack_time, m)?)?;
    m.add_function(wrap_pyfunction!(derive_scrypt_key, m)?)?;
    Ok(())
}
