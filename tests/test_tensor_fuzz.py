import json
import struct
from pathlib import Path

import pytest

from aibom_inspector.tensor_fuzz import (
    SafetensorsDataError,
    SafetensorsHeaderError,
    inspect_weight_file,
    inspect_weight_files,
)


def _write_safetensors(path: Path, tensors: dict[str, bytes]) -> None:
    header = {}
    offset = 0
    data_blobs = []
    for name, blob in tensors.items():
        header[name] = {
            "dtype": "F32",
            "shape": [len(blob) // 4],
            "data_offsets": [offset, offset + len(blob)],
        }
        data_blobs.append(blob)
        offset += len(blob)

    header_bytes = json.dumps(header).encode("utf-8")
    path.write_bytes(len(header_bytes).to_bytes(8, "little") + header_bytes + b"".join(data_blobs))


def test_inspect_weight_file_detects_clean_tensor(tmp_path: Path):
    target = tmp_path / "clean.safetensors"
    values = struct.pack("<4f", 1.0, 2.0, 3.0, 4.0)
    _write_safetensors(target, {"demo": values})

    result = inspect_weight_file(target, sample_limit=10)
    assert result.path == target
    assert not result.suspected
    assert result.tensors[0].nan_count == 0
    assert 0.0 <= result.tensors[0].lsb_ones_ratio <= 1.0


def test_inspect_weight_file_flags_suspicious_bits(tmp_path: Path):
    target = tmp_path / "weird.safetensors"
    bits = [0x3F800001 for _ in range(16)]  # tweak LSBs of 1.0f
    floats_as_bytes = b"".join(struct.pack("<f", struct.unpack("<f", struct.pack("<I", b))[0]) for b in bits)
    nan_blob = struct.pack("<f", float("nan"))
    _write_safetensors(target, {"stego": floats_as_bytes, "poison": nan_blob})

    result = inspect_weight_file(target, sample_limit=64)
    flagged = {t.name: t for t in result.tensors}
    assert flagged["stego"].suspected_steg
    assert flagged["poison"].suspected_poison
    assert result.suspected


def test_batch_inspection_handles_multiple_files(tmp_path: Path):
    one = tmp_path / "one.safetensors"
    two = tmp_path / "two.safetensors"
    blob = struct.pack("<2f", 0.5, 1.5)
    _write_safetensors(one, {"a": blob})
    _write_safetensors(two, {"b": blob})

    results = inspect_weight_files([one, str(two)], sample_limit=2)
    assert len(results) == 2
    assert all(not res.suspected for res in results)


def test_inspect_weight_file_rejects_unsupported_dtype(tmp_path: Path):
    target = tmp_path / "bad_dtype.safetensors"
    header = {"bad": {"dtype": "I64", "shape": [1], "data_offsets": [0, 8]}}
    header_bytes = json.dumps(header).encode("utf-8")
    target.write_bytes(len(header_bytes).to_bytes(8, "little") + header_bytes + b"12345678")

    with pytest.raises(SafetensorsHeaderError):
        inspect_weight_file(target)


def test_inspect_weight_file_detects_truncated_tensor(tmp_path: Path):
    target = tmp_path / "truncated.safetensors"
    header = {"tiny": {"dtype": "F32", "shape": [2], "data_offsets": [0, 8]}}
    header_bytes = json.dumps(header).encode("utf-8")
    # Only 4 bytes of data for a tensor that claims to have 8 bytes
    target.write_bytes(len(header_bytes).to_bytes(8, "little") + header_bytes + b"\x00\x00\x80?")

    with pytest.raises(SafetensorsDataError):
        inspect_weight_file(target, sample_limit=10)
