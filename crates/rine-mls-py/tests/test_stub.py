"""The `.pyi` must describe the module that actually shipped.

PyO3 generates no stubs, so `rine_mls.pyi` is written by hand — which means it
can drift. It cannot drift silently: this compares the stub against the imported
extension in both directions, so a method added to the binding without a stub
entry, or a stub entry for something that no longer exists, fails here.

It also proves the stub is *in the wheel* — it is read from beside the compiled
module in site-packages, not from the source tree.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
import rine_mls

# Compiled in only under the `panic-probe` feature, and deliberately absent from
# every published artifact, so it is not part of the typed surface.
NOT_PUBLIC_API = {"panic_probe"}

# maturin wraps the compiled module in a package whose `__init__` re-exports it,
# which leaves the submodule bound under its own name. A packaging artifact, not
# API — importing `rine_mls.rine_mls` is not something to type or to document.
NOT_MODULE_API = {"rine_mls"}


@pytest.fixture(scope="module")
def stub() -> ast.Module:
    installed = Path(rine_mls.__file__).parent
    path = installed / "__init__.pyi"

    assert path.is_file(), f"no stub shipped beside the extension at {path}"
    assert (installed / "py.typed").is_file(), "stubs without py.typed are invisible to checkers"

    return ast.parse(path.read_text(encoding="utf-8"))


def stub_top_level(stub: ast.Module) -> set[str]:
    names: set[str] = set()
    for node in stub.body:
        if isinstance(node, (ast.ClassDef, ast.FunctionDef)):
            names.add(node.name)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
    return names


def stub_members(stub: ast.Module, class_name: str) -> set[str]:
    for node in stub.body:
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            return {
                child.name
                for child in node.body
                if isinstance(child, ast.FunctionDef) and not child.name.startswith("_")
            } | {
                child.target.id
                for child in node.body
                if isinstance(child, ast.AnnAssign) and isinstance(child.target, ast.Name)
            }
    raise AssertionError(f"{class_name} is not in the stub")


def module_public() -> set[str]:
    return {
        name for name in dir(rine_mls) if not name.startswith("_") and name not in NOT_MODULE_API
    }


def class_public(cls: type) -> set[str]:
    inherited = set(dir(Exception)) | set(dir(object))
    return {
        name
        for name in dir(cls)
        if not name.startswith("_") and name not in inherited and name not in NOT_PUBLIC_API
    }


def test_stub_when_compared_to_the_module_declares_every_public_name(stub):
    assert module_public() == stub_top_level(stub)


@pytest.mark.parametrize("class_name", [
        "MlsClient",
        "MlsGroup",
        "CommitBundle",
        "AppMessage",
        "EscrowExport",
        "EscrowGap",
        "EscrowGapReason",
        "EscrowTake",
        "EscrowBacklog",
        "OpenedMessage",
        "AllowedIdentities",
        "EpochReader",
    ])
def test_stub_when_compared_to_a_class_declares_every_public_member(stub, class_name):
    cls = getattr(rine_mls, class_name)

    assert class_public(cls) == stub_members(stub, class_name)


def test_stub_when_it_names_an_exception_class_that_class_exists(stub):
    declared = {
        node.name
        for node in stub.body
        if isinstance(node, ast.ClassDef) and node.name.endswith("Error")
    }

    for name in declared:
        cls = getattr(rine_mls, name)
        assert issubclass(cls, rine_mls.RineMlsError)


def test_stub_when_it_promises_code_on_the_base_every_raised_error_carries_one(stub, workspace):
    # `code: str` on `RineMlsError` is the promise that a caller which caught
    # only the base class still learns which failure it was — so it has to be on
    # the instance, not just on the classes that happen to be mapped.
    assert "code" in stub_members(stub, "RineMlsError")

    try:
        rine_mls.MlsClient(
            str(workspace / "a"),
            b"agent",
            b"too short",
            rine_mls.AllowedIdentities(),
            rine_mls.CIPHER_SUITE_DEFAULT,
        )
        raise AssertionError("expected a typed refusal")
    except rine_mls.RineMlsError as e:
        assert e.code == "RINE_MLS_INVALID_SIGNING_SEED"
        assert type(e).code == e.code, "class and instance must not disagree"
