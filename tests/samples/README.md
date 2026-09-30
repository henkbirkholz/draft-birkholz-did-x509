# Test vectors

`test-vectors.json` is imported unmodified from the upstream
[microsoft/did-x509](https://github.com/microsoft/did-x509) repository, which
is the authoritative reference implementation for the `did:x509` method
described in this draft.

- Source: https://raw.githubusercontent.com/microsoft/did-x509/`<commit>`/test-vectors.json
- Pinned commit: recorded in [`UPSTREAM_COMMIT`](UPSTREAM_COMMIT) (single
  source of truth; also used to install the pinned reference implementation
  and its `requirements.txt` for comparison, see `tests/test_rego_policy.py`
  and [`tests/README.md`](../README.md)).

microsoft/did-x509 is licensed under the MIT License; see
[`../LICENSE-did-x509`](../LICENSE-did-x509).

## Re-importing at a newer upstream commit

Run, from the repository root:

```sh
$ make update-test-vectors COMMIT=<new-upstream-ref>
```

or, to re-fetch at the currently pinned commit:

```sh
$ make update-test-vectors
```

`<new-upstream-ref>` may be a full commit SHA, or a branch or tag name, which
is resolved to a full commit SHA before anything is updated (see
[`scripts/update-test-vectors.sh`](../../scripts/update-test-vectors.sh)).
This downloads `test-vectors.json` from upstream and updates
`UPSTREAM_COMMIT` to match, only once the download has succeeded.

The draft's `DID-X509-SPEC` and `TEST-VECTORS` references name the same
commit, and `tests/test_upstream_pin.py` fails until they match. Update them
when the draft is re-aligned with the newer upstream commit.
