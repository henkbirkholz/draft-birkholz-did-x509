"""Checks that the draft cites the upstream commit the tests are pinned to.

tests/samples/UPSTREAM_COMMIT pins the imported test vectors and the
reference implementation. The draft's DID-X509-SPEC and TEST-VECTORS
references name the same commit, so moving the pin without re-aligning
the draft makes this test fail.
"""

import re
from pathlib import Path

import pytest

TESTS_DIR = Path(__file__).resolve().parent
DRAFT = TESTS_DIR.parent / "draft-birkholz-did-x509.md"
UPSTREAM_COMMIT = (TESTS_DIR / "samples" / "UPSTREAM_COMMIT").read_text(
    encoding="utf-8"
).strip()


def test_pin_is_a_full_commit_sha():
    assert re.fullmatch(r"[0-9a-f]{40}", UPSTREAM_COMMIT), UPSTREAM_COMMIT


@pytest.mark.parametrize("anchor", ["DID-X509-SPEC", "TEST-VECTORS"])
def test_reference_names_pinned_commit(anchor):
    front_matter = DRAFT.read_text(encoding="utf-8").split("\n--- abstract", 1)[0]
    match = re.search(
        rf"^  {re.escape(anchor)}:\n    target: (\S+)$", front_matter, re.MULTILINE
    )
    assert match, f"The draft has no {anchor} reference with a target."
    assert f"/blob/{UPSTREAM_COMMIT}/" in match[1], (
        f"{anchor} points to {match[1]}, but tests/samples/UPSTREAM_COMMIT is "
        f"{UPSTREAM_COMMIT}."
    )
