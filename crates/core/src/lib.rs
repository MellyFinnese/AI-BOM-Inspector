use half::{bf16, f16};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyModule};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

#[derive(Debug, Deserialize)]
struct TensorHeader {
    dtype: String,
    data_offsets: (u64, u64),
    _shape: Vec<usize>,
}

#[derive(Debug)]
struct TensorStats {
    name: String,
    dtype: String,
    elements: u64,
    sampled: u64,
    nan_count: u64,
    inf_count: u64,
    lsb_ones: u64,
    lsb_zero: u64,
}

fn dtype_size(dtype: &str) -> Option<u64> {
    match dtype.to_ascii_uppercase().as_str() {
        "F16" | "BF16" => Some(2),
        "F32" => Some(4),
        "F64" => Some(8),
        _ => None,
    }
}

fn parse_header(mut file: &File) -> PyResult<(HashMap<String, TensorHeader>, u64)> {
    let mut header_len_buf = [0u8; 8];
    file.read_exact(&mut header_len_buf).map_err(|e| {
        PyErr::new::<pyo3::exceptions::PyIOError, _>(format!(
            "Failed to read safetensors header length: {e}"
        ))
    })?;
    let header_len = u64::from_le_bytes(header_len_buf);
    if header_len > 64 * 1024 * 1024 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            "Unreasonably large safetensors header; refusing to parse.",
        ));
    }

    let mut header_buf = vec![0u8; header_len as usize];
    file.read_exact(&mut header_buf).map_err(|e| {
        PyErr::new::<pyo3::exceptions::PyIOError, _>(format!(
            "Failed to read safetensors header: {e}"
        ))
    })?;
    let header: HashMap<String, TensorHeader> =
        serde_json::from_slice(&header_buf).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                "Unable to parse safetensors header JSON: {e}"
            ))
        })?;

    Ok((header, 8 + header_len))
}

fn analyze_tensor(
    file: &mut File,
    name: &str,
    meta: &TensorHeader,
    base_offset: u64,
    sample_limit: u64,
) -> PyResult<TensorStats> {
    let dtype_bytes = dtype_size(&meta.dtype).ok_or_else(|| {
        PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
            "Unsupported dtype '{}' for tensor '{}'",
            meta.dtype, name
        ))
    })?;

    let (start, end) = meta.data_offsets;
    if end <= start {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
            "Invalid data offsets for tensor '{name}'"
        )));
    }
    let data_len = end - start;
    let total_values = data_len / dtype_bytes;
    if total_values == 0 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
            "Tensor '{name}' reports zero elements"
        )));
    }

    let mut nan_count = 0u64;
    let mut inf_count = 0u64;
    let mut lsb_ones = 0u64;
    let mut lsb_zero = 0u64;

    let mut processed = 0u64;
    let max_values = sample_limit.min(total_values);
    let mut buf = vec![0u8; (dtype_bytes as usize).min(8192)];
    let block_values = ((buf.len() as u64) / dtype_bytes).max(1);
    let chunk_count = ((max_values + block_values - 1) / block_values).max(1);
    let mut chunk_index = 0u64;

    while processed < max_values {
        let remaining = max_values - processed;
        let values_to_read = remaining.min(block_values);
        let start_value = if chunk_count <= 1 {
            0
        } else {
            (chunk_index * total_values.saturating_sub(values_to_read)) / (chunk_count - 1)
        };

        file.seek(SeekFrom::Start(
            base_offset + start + start_value.saturating_mul(dtype_bytes),
        ))
        .map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyIOError, _>(format!(
                "Unable to seek to tensor '{name}': {e}"
            ))
        })?;

        let bytes_to_read = (values_to_read * dtype_bytes) as usize;
        let slice = &mut buf[..bytes_to_read];
        file.read_exact(slice).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyIOError, _>(format!(
                "Failed reading tensor '{name}': {e}"
            ))
        })?;

        for chunk in slice.chunks(dtype_bytes as usize) {
            match dtype_bytes {
                2 => {
                    let raw = u16::from_le_bytes([chunk[0], chunk[1]]);
                    let bits = if meta.dtype.eq_ignore_ascii_case("BF16") {
                        bf16::from_bits(raw).to_f32().to_bits()
                    } else {
                        f16::from_bits(raw).to_f32().to_bits()
                    };
                    let value = f32::from_bits(bits);
                    if value.is_nan() {
                        nan_count += 1;
                    } else if value.is_infinite() {
                        inf_count += 1;
                    }
                    if bits & 1 == 1 {
                        lsb_ones += 1;
                    } else {
                        lsb_zero += 1;
                    }
                }
                4 => {
                    let raw = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                    let value = f32::from_bits(raw);
                    if value.is_nan() {
                        nan_count += 1;
                    } else if value.is_infinite() {
                        inf_count += 1;
                    }
                    if raw & 1 == 1 {
                        lsb_ones += 1;
                    } else {
                        lsb_zero += 1;
                    }
                }
                8 => {
                    let raw = u64::from_le_bytes([
                        chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6],
                        chunk[7],
                    ]);
                    let value = f64::from_bits(raw);
                    if value.is_nan() {
                        nan_count += 1;
                    } else if value.is_infinite() {
                        inf_count += 1;
                    }
                    if raw & 1 == 1 {
                        lsb_ones += 1;
                    } else {
                        lsb_zero += 1;
                    }
                }
                _ => unreachable!(),
            }
            processed += 1;
            if processed >= max_values {
                break;
            }
        }

        chunk_index += 1;
    }

    Ok(TensorStats {
        name: name.to_string(),
        dtype: meta.dtype.clone(),
        elements: total_values,
        sampled: max_values,
        nan_count,
        inf_count,
        lsb_ones,
        lsb_zero,
    })
}

fn stats_to_dict(py: Python<'_>, stats: TensorStats) -> PyResult<Py<PyDict>> {
    let lsb_total = stats.lsb_ones + stats.lsb_zero;
    let lsb_ratio = if lsb_total == 0 {
        0.0_f64
    } else {
        stats.lsb_ones as f64 / lsb_total as f64
    };
    let suspected_steg = lsb_total >= 16 && (lsb_ratio < 0.25 || lsb_ratio > 0.75);
    let suspected_poison = stats.nan_count > 0 || stats.inf_count > 0;

    let dict = PyDict::new(py);
    dict.set_item("name", stats.name)?;
    dict.set_item("dtype", stats.dtype)?;
    dict.set_item("elements", stats.elements)?;
    dict.set_item("sampled", stats.sampled)?;
    dict.set_item("nan_count", stats.nan_count)?;
    dict.set_item("inf_count", stats.inf_count)?;
    dict.set_item("lsb_ones_ratio", lsb_ratio)?;
    dict.set_item("suspected_steg", suspected_steg)?;
    dict.set_item("suspected_poison", suspected_poison)?;
    Ok(dict.unbind())
}

#[pyfunction]
fn inspect_file(py: Python<'_>, path: &str, sample_limit: Option<u64>) -> PyResult<Py<PyDict>> {
    let mut file = File::open(path).map_err(|e| {
        PyErr::new::<pyo3::exceptions::PyIOError, _>(format!(
            "Unable to open safetensors file {path}: {e}"
        ))
    })?;
    let (header, base_offset) = parse_header(&file)?;

    let sample_limit = sample_limit.unwrap_or(1_000_000);
    let mut tensors = Vec::new();
    for (name, meta) in header.iter() {
        match analyze_tensor(&mut file, name, meta, base_offset, sample_limit) {
            Ok(stats) => tensors.push(stats),
            Err(err) => return Err(err),
        }
    }

    let overall_suspect = tensors.iter().any(|stats| {
        let lsb_total = stats.lsb_ones + stats.lsb_zero;
        let lsb_ratio = if lsb_total == 0 {
            0.0_f64
        } else {
            stats.lsb_ones as f64 / lsb_total as f64
        };
        let suspected_steg = lsb_total >= 16 && (lsb_ratio < 0.25 || lsb_ratio > 0.75);
        let suspected_poison = stats.nan_count > 0 || stats.inf_count > 0;
        suspected_steg || suspected_poison
    });

    let py_tensors: Vec<Py<PyDict>> = tensors
        .into_iter()
        .map(|s| stats_to_dict(py, s))
        .collect::<PyResult<_>>()?;

    let result = PyDict::new(py);
    result.set_item("path", path)?;
    result.set_item("tensors", &py_tensors)?;
    result.set_item("suspected", overall_suspect)?;

    Ok(result.unbind())
}

#[pymodule]
fn _tensor_fuzz(_py: Python<'_>, m: &Bound<PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(inspect_file, m)?)?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add("__doc__", "Safetensors fuzzing helpers built in Rust")?;
    Ok(())
}
