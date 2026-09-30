# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License; see LICENSE-did-x509.
#
# Adapted from upstream microsoft/did-x509's test_specification_rego.py
# (the Rego checks) and test_vectors.py (load_vector_chain), pinned via
# samples/UPSTREAM_COMMIT. Unlike upstream, which extracts its Rego
# policy from its own specification.md by regex, this assembles the
# policy from the draft's own figures, extracted by
# kramdown-rfc-extract-sourcecode into figures/rego/ (see policy_file
# below); test vectors are read from samples/test-vectors.json instead
# of upstream's own copy.

import base64
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from cryptography import x509

from didx509.didx509 import check_did_x509, decode_certificate

REPO_ROOT = Path(__file__).resolve().parents[1]
FIGURES_REGO_DIR = REPO_ROOT / "figures" / "rego"
SAMPLES_FILE = Path(__file__).resolve().parent / "samples" / "test-vectors.json"

with SAMPLES_FILE.open() as vectors_file:
    TEST_VECTORS = json.load(vectors_file)


@pytest.fixture(scope="module")
def opa():
    path = shutil.which("opa")
    if path is None:
        pytest.fail(
            "OPA is not on PATH; install OPA 1.21.0 (see tests/README.md)."
        )
    return path


@pytest.fixture(scope="module")
def policy_file(tmp_path_factory):
    """Assemble the draft's Rego figures into a single policy file.

    Each figure is extracted by kramdown-rfc-extract-sourcecode into its own
    file under figures/rego/, named after its descriptive artwork-name. The
    overall policy is these files concatenated, with the package-declaring
    (core) file first, as described in the draft.
    """
    rego_files = sorted(FIGURES_REGO_DIR.glob("*.rego"))
    if not rego_files:
        pytest.fail(
            f"No *.rego files found under {FIGURES_REGO_DIR}; run "
            "`make draft-birkholz-did-x509.xml` and "
            "`kramdown-rfc-extract-sourcecode -t files -d figures "
            "draft-birkholz-did-x509.xml` first."
        )
    core_files = [
        f
        for f in rego_files
        if re.search(r"^package\s+\S+", f.read_text(encoding="utf-8"), re.MULTILINE)
    ]
    assert len(core_files) == 1, (
        f"Expected exactly one Rego figure with a package declaration, "
        f"found {len(core_files)}: {core_files}"
    )
    ordered_files = core_files + [f for f in rego_files if f not in core_files]
    combined = "\n".join(f.read_text(encoding="utf-8") for f in ordered_files)
    path = tmp_path_factory.mktemp("specification") / "policy.rego"
    path.write_text(combined, encoding="utf-8")
    return path


@pytest.fixture(scope="module")
def policy_package(policy_file):
    package = re.search(
        r"^package\s+(\S+)", policy_file.read_text(encoding="utf-8"), re.MULTILINE
    )
    assert package, "The Rego policy has no package declaration."
    return package[1]


def test_policy_compiles(opa, policy_file):
    result = subprocess.run(
        [opa, "check", "--strict", str(policy_file)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr


def load_vector_chain(vector):
    def decode(value):
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))

    return [
        x509.load_der_x509_certificate(decode(certificate))
        for certificate in vector["input"]["chain"]
    ]


@pytest.mark.parametrize(
    "vector",
    [pytest.param(vector, id=vector["id"]) for vector in TEST_VECTORS],
)
def test_policy_matches_implementation(opa, policy_file, policy_package, vector):
    chain = load_vector_chain(vector)
    try:
        model = [decode_certificate(certificate) for certificate in chain]
    except (ValueError, RuntimeError) as e:
        pytest.skip(f"The chain cannot be mapped to the JSON model: {e}")

    did = vector["input"]["did"]
    try:
        check_did_x509(did, chain)
        expected = True
    except ValueError:
        expected = False
    if "document" in vector["output"]:
        assert expected

    result = subprocess.run(
        [
            opa,
            "eval",
            "--format",
            "json",
            "--stdin-input",
            "--data",
            str(policy_file),
            f"data.{policy_package}.valid",
        ],
        input=json.dumps({"did": did.split("#", 1)[0], "chain": model}),
        capture_output=True,
        text=True,
        timeout=30,
    )
    # opa eval reports evaluation errors on stdout when using --format json.
    assert result.returncode == 0, result.stdout + result.stderr
    output = json.loads(result.stdout)
    valid = (
        "result" in output and output["result"][0]["expressions"][0]["value"] is True
    )
    assert valid == expected
