from __future__ import annotations

import pickle

import pytest

from aibom_inspector.pickle_inspector import _scan_globals


class _ReduceRef:
    """A tiny helper whose __reduce__ makes pickle emit a GLOBAL/STACK_GLOBAL
    reference to an arbitrary callable, without ever calling it.

    IMPORTANT: pickle.dumps() only calls __reduce__() to discover what to
    serialize; it never invokes the referenced callable. These fixtures are
    therefore safe to build. The resulting bytes must never be passed to
    pickle.load()/pickle.loads() in these tests -- only to the opcode-level
    scanner, which never executes anything.
    """

    def __init__(self, target, args=()):
        self._target = target
        self._args = args

    def __reduce__(self):
        return (self._target, self._args)


def _build_pickle(target, args=(), *, protocol: int) -> bytes:
    return pickle.dumps(_ReduceRef(target, args), protocol=protocol)


# Process-launch primitives that a real adversarial pickle could reference.
# Each entry is (label, callable, args-tuple-for-reduce).
import os
import subprocess

DANGEROUS_CALLABLES = [
    ("subprocess.Popen", subprocess.Popen, ([],)),
    ("subprocess.run", subprocess.run, ([],)),
    ("subprocess.call", subprocess.call, ([],)),
    ("subprocess.check_call", subprocess.check_call, ([],)),
    ("subprocess.check_output", subprocess.check_output, ([],)),
    ("os.system", os.system, ("id",)),
    ("os.popen", os.popen, ("id",)),
    ("os.execv", os.execv, ("/bin/sh", [])),
    ("os.execve", os.execve, ("/bin/sh", [], {})),
    ("os.execvp", os.execvp, ("sh", [])),
    ("os.execvpe", os.execvpe, ("sh", [], {})),
    ("os.posix_spawn", os.posix_spawn, ("/bin/sh", [], {})),
]


@pytest.mark.parametrize("label,target,args", DANGEROUS_CALLABLES)
@pytest.mark.parametrize("protocol", [0, 4])
def test_dangerous_process_launch_primitives_are_detected(label, target, args, protocol):
    data = _build_pickle(target, args, protocol=protocol)

    findings = _scan_globals(data)

    assert findings, f"{label} at protocol {protocol} should be flagged as dangerous but was not detected"


def test_benign_global_reference_is_not_flagged():
    # collections.OrderedDict is an extremely common, entirely benign global
    # reference found in ordinary (non-malicious) pickles and must not be
    # flagged as dangerous.
    from collections import OrderedDict

    data = _build_pickle(OrderedDict, (), protocol=4)
    findings = _scan_globals(data)

    assert not findings
