from __future__ import annotations

import pickle

import pytest

from aibom_inspector.pickle_inspector import (
    PickleFileTooLargeError,
    inspect_pickle_file,
    inspect_pickle_files,
)


def test_inspect_pickle_file_respects_max_size(tmp_path):
    data = pickle.dumps({"payload": "x" * 32})
    target = tmp_path / "large.pkl"
    target.write_bytes(data)

    with pytest.raises(PickleFileTooLargeError):
        inspect_pickle_file(target, max_bytes=16)


def test_inspect_pickle_files_allow_disable_limit(tmp_path):
    data = pickle.dumps([1, 2, 3])
    target = tmp_path / "small.pkl"
    target.write_bytes(data)

    results = inspect_pickle_files([target], max_bytes=None)
    assert len(results) == 1
    assert not results[0].suspected
