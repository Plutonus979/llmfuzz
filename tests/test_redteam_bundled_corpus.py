from __future__ import annotations

import builtins
import hashlib
import tomllib
from collections import Counter
from importlib import resources
from pathlib import Path

import pytest

from llmfuzz.redteam_corpus import (
    ACCEPTED_CORPUS_SHA256,
    ASSERTION_VOCABULARY,
    ATTACK_CLASSES,
    CORPUS_SCHEMA_VERSION,
    CorpusValidationError,
    canonical_persisted_bytes,
    load_bundled_accepted_corpus,
    load_corpus,
)


RAW_PERSISTED_SHA256 = "15d5a23bcd87cdf7c12a7557bf2c8d738199f5dd2a5c393c94d49462f412b461"


def _resource():
    return resources.files("llmfuzz").joinpath("data", "accepted-corpus.v1.json")


def test_bundled_accepted_corpus_identity_and_contract() -> None:
    data = _resource().read_bytes()
    corpus = load_bundled_accepted_corpus()
    with resources.as_file(_resource()) as path:
        loaded_directly = load_corpus(path)

    assert hashlib.sha256(data).hexdigest() == RAW_PERSISTED_SHA256
    assert loaded_directly == corpus
    assert corpus.schema_version == CORPUS_SCHEMA_VERSION
    assert corpus.corpus_sha256 == ACCEPTED_CORPUS_SHA256
    assert data == canonical_persisted_bytes(corpus)
    assert corpus.generation_metadata.model == "gpt-5.6-sol"
    assert corpus.generation_metadata.requested_case_count == 16
    assert corpus.generation_metadata.generated_case_count == 16
    assert len(corpus.cases) == 16
    assert len({case.case_id for case in corpus.cases}) == 16
    assert Counter(case.attack_class for case in corpus.cases) == {
        attack_class: 4 for attack_class in ATTACK_CLASSES
    }
    assert {
        assertion for case in corpus.cases for assertion in case.assertions
    } == set(ASSERTION_VOCABULARY)


def test_bundled_lookup_is_independent_of_current_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    assert load_bundled_accepted_corpus().corpus_sha256 == ACCEPTED_CORPUS_SHA256


def test_one_byte_tampered_bundled_copy_is_rejected(tmp_path: Path) -> None:
    tampered = bytearray(_resource().read_bytes())
    tampered[-1] = ord(" ")
    path = tmp_path / "tampered.json"
    path.write_bytes(tampered)

    with pytest.raises(CorpusValidationError):
        load_corpus(path)


def test_bundled_lookup_does_not_import_or_initialize_openai(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    imported_optional: list[str] = []
    real_import = builtins.__import__

    def guarded_import(name: str, *args: object, **kwargs: object) -> object:
        if name == "openai" or name.startswith("openai."):
            imported_optional.append(name)
            raise AssertionError("bundled corpus loading must remain offline")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-present-key")

    assert load_bundled_accepted_corpus().corpus_sha256 == ACCEPTED_CORPUS_SHA256
    assert imported_optional == []


def test_package_configuration_includes_only_optional_openai_dependency() -> None:
    repository = Path(__file__).resolve().parents[1]
    configuration = tomllib.loads((repository / "pyproject.toml").read_text(encoding="utf-8"))
    package_data = configuration["tool"]["setuptools"]["package-data"]["llmfuzz"]
    manifest = (repository / "MANIFEST.in").read_text(encoding="utf-8").splitlines()

    assert "data/*.json" in package_data
    assert "include llmfuzz/data/*.json" in manifest
    assert "dependencies" not in configuration["project"]
    assert configuration["project"]["optional-dependencies"]["openai"] == [
        "openai>=2.46.0,<3"
    ]
