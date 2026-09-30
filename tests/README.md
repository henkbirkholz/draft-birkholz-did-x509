# Tests

`test_rego_policy.py` checks the draft's Rego policy with `opa check --strict`
and evaluates it against test vectors imported from the upstream
[microsoft/did-x509](https://github.com/microsoft/did-x509) reference
implementation (see [`samples/README.md`](samples/README.md) for
provenance and [`LICENSE-did-x509`](LICENSE-did-x509) for attribution).

`test_upstream_pin.py` checks that the draft's references to the upstream
specification and test vectors name the commit recorded in
[`samples/UPSTREAM_COMMIT`](samples/UPSTREAM_COMMIT).

To run the tests locally, first build the XML and extract figures:

```sh
$ make draft-birkholz-did-x509.xml
$ kramdown-rfc-extract-sourcecode -t files -d figures draft-birkholz-did-x509.xml
```

Then install the pinned reference implementation and its own dependency
pins, and run the tests:

```sh
$ COMMIT=$(cat tests/samples/UPSTREAM_COMMIT)
$ pip install -r "https://raw.githubusercontent.com/microsoft/did-x509/$COMMIT/requirements.txt"
$ pip install "git+https://github.com/microsoft/did-x509@$COMMIT"
$ pytest tests -v
```

The Rego test requires an [OPA](https://www.openpolicyagent.org/) binary
(version 1.21.0, matching CI) on `PATH`. CI uses Python 3.14.
