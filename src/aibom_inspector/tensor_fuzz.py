from __future__ import annotations

import json
import struct
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List

try:  # pragma: no cover - optional Rust acceleration
    from . import _tensor_fuzz  # type: ignore
except Exception as exc:  # pragma: no cover - handled gracefully below
    _tensor_fuzz = None
    warnings.warn(
        f"Falling back to pure-Python tensor inspection because the Rust extension failed to load: {exc}",
        RuntimeWarning,
    )


@dataclass
class TensorAnomaly:
    name: str
    dtype: str
    elements: int
    sampled: int
    nan_count: int
    inf_count: int
    lsb_ones_ratio: float
    suspected_steg: bool
    suspected_poison: bool

    @classmethod
    def from_mapping(cls, data: Dict) -> "TensorAnomaly":
        return cls(
            name=data.get("name", "unknown"),
            dtype=str(data.get("dtype", "unknown")),
            elements=int(data.get("elements", 0)),
            sampled=int(data.get("sampled", 0)),
            nan_count=int(data.get("nan_count", 0)),
            inf_count=int(data.get("inf_count", 0)),
            lsb_ones_ratio=float(data.get("lsb_ones_ratio", 0.0)),
            suspected_steg=bool(data.get("suspected_steg", False)),
            suspected_poison=bool(data.get("suspected_poison", False)),
        )


@dataclass
class WeightScanResult:
    path: Path
    tensors: List[TensorAnomaly] = field(default_factory=list)
    suspected: bool = False

    @property
    def flagged_tensors(self) -> List[TensorAnomaly]:
        return [t for t in self.tensors if t.suspected_poison or t.suspected_steg]

    def as_dict(self) -> Dict:
        return {
            "path": str(self.path),
            "suspected": self.suspected,
            "tensors": [t.__dict__ for t in self.tensors],
        }


_SUPPORTED_DTYPES = {
    "F16": ("<e", 2),
    "BF16": ("<e", 2),
    "F32": ("<f", 4),
    "F64": ("<d", 8),
}


class SafetensorsHeaderError(ValueError):
    """Raised when a safetensors header is invalid."""


class SafetensorsDataError(IOError):
    """Raised when safetensors data cannot be decoded."""


def _load_header(path: Path) -> tuple[dict, int]:
    with path.open("rb") as handle:
        header_len_raw = handle.read(8)
        if len(header_len_raw) != 8:
            raise SafetensorsHeaderError("Unable to read safetensors header length")
        header_len = int.from_bytes(header_len_raw, "little")
        if header_len <= 0 or header_len > 64 * 1024 * 1024:
            raise SafetensorsHeaderError("Safetensors header length is not credible")

        header_bytes = handle.read(header_len)
        if len(header_bytes) != header_len:
            raise SafetensorsHeaderError("Safetensors header truncated")

        try:
            header = json.loads(header_bytes.decode("utf-8"))
        except Exception as exc:  # pragma: no cover - defensive
            raise SafetensorsHeaderError(f"Invalid safetensors header JSON: {exc}") from exc

    return header, 8 + header_len


def _lsb_ratio_from_bytes(data: bytes, fmt: str) -> tuple[int, int, int, int]:
    size = struct.calcsize(fmt)
    nan_count = 0
    inf_count = 0
    lsb_ones = 0
    lsb_zero = 0

    for offset in range(0, len(data), size):
        chunk = data[offset : offset + size]
        if len(chunk) < size:
            break
        if fmt == "<e":  # half precision encoded as little-endian 16-bit
            raw = struct.unpack("<H", chunk)[0]
            # BF16 and F16 get treated the same for bit inspection.
            value = struct.unpack("<e", chunk)[0]
            if value != value:  # NaN
                nan_count += 1
            elif value in {float("inf"), float("-inf")}:
                inf_count += 1
            if raw & 1:
                lsb_ones += 1
            else:
                lsb_zero += 1
            continue
        raw_val = struct.unpack(fmt, chunk)[0]
        raw_bits = struct.unpack("<I" if fmt == "<f" else "<Q", chunk)[0]
        if raw_val != raw_val:
            nan_count += 1
        elif raw_val in {float("inf"), float("-inf")}:
            inf_count += 1
        if raw_bits & 1:
            lsb_ones += 1
        else:
            lsb_zero += 1

    return nan_count, inf_count, lsb_ones, lsb_zero


def _python_inspect(path: Path, sample_limit: int = 1_000_000) -> WeightScanResult:
    header, base_offset = _load_header(path)
    tensors: List[TensorAnomaly] = []

    with path.open("rb") as handle:
        for name, meta in header.items():
            dtype = str(meta.get("dtype", "")).upper()
            if dtype not in _SUPPORTED_DTYPES:
                raise SafetensorsHeaderError(f"Unsupported dtype '{dtype}' for tensor '{name}'")
            fmt, size = _SUPPORTED_DTYPES[dtype]
            start, end = meta.get("data_offsets", [0, 0])
            if not isinstance(start, int) or not isinstance(end, int) or end <= start:
                raise SafetensorsHeaderError(f"Invalid data offsets for tensor '{name}'")

            total_bytes = end - start
            elements = total_bytes // size
            target_samples = min(elements, sample_limit)
            processed = 0
            block_values = max(1, (8192 // size))
            buffer = bytearray(block_values * size)
            chunk_count = max(1, (target_samples + block_values - 1) // block_values)
            chunk_index = 0

            nan_count = 0
            inf_count = 0
            lsb_ones = 0
            lsb_zero = 0

            while processed < target_samples:
                remaining = target_samples - processed
                values_to_read = min(remaining, block_values)
                available_span = max(elements - values_to_read, 0)
                start_value = 0 if chunk_count <= 1 else chunk_index * available_span // (chunk_count - 1)

                handle.seek(base_offset + start + start_value * size)
                view = memoryview(buffer)[: values_to_read * size]
                read_bytes = handle.readinto(view)
                if read_bytes != values_to_read * size:
                    raise SafetensorsDataError(f"Tensor '{name}' terminated early during read")

                chunk_nan, chunk_inf, chunk_lsb_ones, chunk_lsb_zero = _lsb_ratio_from_bytes(bytes(view), fmt)
                nan_count += chunk_nan
                inf_count += chunk_inf
                lsb_ones += chunk_lsb_ones
                lsb_zero += chunk_lsb_zero
                processed += values_to_read
                chunk_index += 1

            sampled = processed
            total_lsb = max(lsb_zero + lsb_ones, 1)
            ratio = lsb_ones / total_lsb
            suspected_steg = total_lsb >= 16 and (ratio < 0.25 or ratio > 0.75)
            suspected_poison = nan_count > 0 or inf_count > 0

            tensors.append(
                TensorAnomaly(
                    name=name,
                    dtype=dtype,
                    elements=int(elements),
                    sampled=int(sampled),
                    nan_count=nan_count,
                    inf_count=inf_count,
                    lsb_ones_ratio=ratio,
                    suspected_steg=suspected_steg,
                    suspected_poison=suspected_poison,
                )
            )

    return WeightScanResult(
        path=path,
        tensors=tensors,
        suspected=any(t.suspected_poison or t.suspected_steg for t in tensors),
    )


def inspect_weight_file(path: Path | str, sample_limit: int = 1_000_000) -> WeightScanResult:
    """Inspect a safetensors file for poisoned neurons or LSB steganography.

    The Rust extension is preferred when available; otherwise a pure-Python
    implementation is used. Only F16/BF16/F32/F64 tensors are currently
    supported for bit-level inspection.
    """

    path = Path(path)
    if _tensor_fuzz:
        raw = _tensor_fuzz.inspect_file(str(path), sample_limit)
        tensors = [TensorAnomaly.from_mapping(t) for t in raw.get("tensors", [])]
        return WeightScanResult(path=path, tensors=tensors, suspected=bool(raw.get("suspected")))
    return _python_inspect(path, sample_limit=sample_limit)


def inspect_weight_files(
    paths: Iterable[Path | str], sample_limit: int = 1_000_000
) -> List[WeightScanResult]:
    results: List[WeightScanResult] = []
    for candidate in paths:
        results.append(inspect_weight_file(candidate, sample_limit=sample_limit))
    return results
