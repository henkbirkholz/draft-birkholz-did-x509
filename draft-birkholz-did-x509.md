---
v: 3

title: "x509 Decentralized Identifier"
abbrev: "did:x509"
docname: draft-birkholz-did-x509-latest
category: std
consensus: true
submissionType: IETF

ipr: trust200902
area: "Security"
keyword: [ DID, X.509,]

stand_alone: yes
smart_quotes: no
pi: [toc, sortrefs, symrefs]

author:
 - name: Maik Riechert
   organization: Microsoft
   email: Maik.Riechert@microsoft.com
 - name: Antoine Delignat-Lavaud
   organization: Microsoft
   email: antdl@microsoft.com
 - name: Henk Birkholz
   organization: Fraunhofer SIT
   email: henk.birkholz@ietf.contact
 - name: Amaury Chamayou
   organization: Microsoft
   email: Amaury.Chamayou@microsoft.com

normative:
  RFC3986: uri
  STD90:
    -: json
    =: RFC8259
  RFC8610: cddl
  RFC9165: cddlplus
  STD94:
    -: cbor
    =: RFC8949
  BCP26:
    -: ianacons
    =: RFC8126
  RFC5234: abnf
  DIDV1:
    target: https://www.w3.org/TR/2022/REC-did-core-20220719/
    title: W3C DID v1.0 specification
  RFC5280:
  VC:
    target: https://www.w3.org/TR/vc-data-model/
    title: W3C Verifiable Credentials

informative:
  I-D.ietf-scitt-architecture: scitt-arch
  REGO:
    target: https://www.openpolicyagent.org/docs/latest/policy-language/
    title: Rego
  RFC9360:
  RFC9597:

entity:
  SELF: "RFCthis"

--- abstract

Some abstract

--- middle

# Introduction

This document aims to define an interoperable and flexible issuer identifier format for COSE messages that transport or refer to X.509 certificates using {{RFC9360}}.
The did:x509 identifier format implements a direct, resolvable binding between a certificate chain and a compact issuer string.
It can be used in a COSE Header CWT Claims map as defined in {{RFC9597}}.
This issuer identifier is convenient for references and policy evaluation, for example in the context of transparency ledgers.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

In this document, CDDL ({{-cddl}}, {{-cddlplus}}) is used to describe the
data formats, and ABNF (defined in {{-abnf}}) to describe identifiers.

The reader is assumed to be familiar with the vocabulary and concepts
defined in {{-scitt-arch}}.

# Identifier Syntax

The did:x509 ABNF definition defined below uses the syntax defined in {{-abnf}} and the corresponding definitions for `ALPHA` and `DIGIT`.
The {{DIDV1}} contains the definition for `idchar`.

~~~abnf
did-x509           = "did:" method-name ":" method-specific-id
method-name        = "x509"
method-specific-id = version ":" ca-fingerprint-alg ":" ca-fingerprint 1*("::" policy-name ":" policy-value)
version            = 1*DIGIT
ca-fingerprint-alg = "sha256" / "sha384" / "sha512"
ca-fingerprint     = base64url
policy-name        = 1*ALPHA
policy-value       = *(1*idchar ":") 1*idchar
base64url          = 1*(ALPHA / DIGIT / "-" / "_")
~~~

In this draft, version is `0`.

`ca-fingerprint-alg` is one of `sha256`, `sha384`, or `sha512`.
`ca-fingerprint` is `chain[i].fingerprint[ca-fingerprint-alg]` with i > 0, that is, either an intermediate or root CA certificate.
`policy-name` is a policy name and `policy-value` is a policy-specific value.
`::` is used to separate multiple policies from each other.

The following sections define the policies and their policy-specific syntax.

Validation of policies is formally defined using {{REGO}} policies, though there is no expectation that implementations use Rego.

The input to the Rego engine is the JSON document `{"did": "<DID>", "chain": <CertificateChain>}`.

Core Rego policy:

~~~rego
parse_did(did) := [ca_fingerprint_alg, ca_fingerprint, policies] if {
    prefix := "did:x509:0:"
    startswith(did, prefix) == true
    rest := trim_prefix(did, prefix)
    parts := split(rest, "::")
    [ca_fingerprint_alg, ca_fingerprint] := split(parts[0], ":")
    policies_raw := array.slice(parts, 1, count(parts))
    policies := [y |
        some i
        s := policies_raw[i]
        j := indexof(s, ":")
        y := [substring(s, 0, j), substring(s, j+1, -1)]
    ]
}

valid if {
    [ca_fingerprint_alg, ca_fingerprint, policies] := parse_did(input.did)
    ca := [c | some i; i != 0; c := input.chain[i]]
    ca[_].fingerprint[ca_fingerprint_alg] == ca_fingerprint
    valid_policies := [i |
        some i
        [name, value] := policies[i]
        validate_policy(name, value)
    ]
    count(valid_policies) == count(policies)
}
~~~

The overall Rego policy is assembled by concatenating the core Rego policy with the Rego policy fragments in the following sections, each one defining a `validate_policy` function.

## Percent-encoding

Some of the policies that are defined in subsequent sections require values to be percent-encoded. Percent-encoding is specified in {{Section 2.1 of RFC3986}}. All characters that are not in the allowed set defined below must be percent-encoded:

~~~abnf
allowed = ALPHA / DIGIT / "-" / "." / "_"
~~~

Note that most libraries implement percent-encoding in the context of URLs and do NOT encode `~` (`%7E`).

## "subject" policy

~~~abnf
policy-name     = "subject"
policy-value    = key ":" value *(":" key ":" value)
key             = label / oid
value           = 1*idchar
label           = "CN" / "L" / "ST" / "O" / "OU" / "C" / "STREET"
oid             = 1*DIGIT *("." 1*DIGIT)
~~~

`<key>:<value>` are the subject name fields in `chain[0].subject` in any order. Field repetitions are not allowed. Values must be percent-encoded.

Example:

`did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk::subject:C:US:ST:California:L:San%20Francisco:O:GitHub%2C%20Inc.`

Rego policy:

~~~rego
validate_policy(name, value) := true if {
    name == "subject"
    items := split(value, ":")
    count(items) % 2 == 0
    subject := {k: v |
        some i
        i % 2 == 0
        k := items[i]
        v := urlquery.decode(items[i+1])
    }
    count(subject) >= 1
    object.subset(input.chain[0].subject, subject) == true
}
~~~

## "san" policy

~~~abnf
policy-name     = "san"
policy-value    = san-type ":" san-value
san-type        = "email" / "dns" / "uri"
san-value       = 1*idchar
~~~

`san-type` is the SAN type and must be one of `email`, `dns`, or `uri`. Note that `dn` is not supported.

`san-value` is the SAN value, percent-encoded.

The pair `[<san_type>, <san_value>]` is one of the items in `chain[0].extensions.san`.

Example:

`did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk::san:email:bob%40example.com`

Rego policy:

~~~rego
validate_policy(name, value) := true if {
    name == "san"
    [san_type, san_value_encoded] := split(value, ":")
    san_value := urlquery.decode(san_value_encoded)
    [san_type, san_value] == input.chain[0].extensions.san[_]
}
~~~

## "eku" policy

~~~abnf
policy-name  = "eku"
policy-value = eku
eku          = oid
oid          = 1*DIGIT *("." 1*DIGIT)
~~~

`eku` is one of the OIDs within `chain[0].extensions.eku`.

Example:

`did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk::eku:1.3.6.1.4.1.311.10.3.13`

Rego policy:

~~~rego
validate_policy(name, value) := true if {
    name == "eku"
    value == input.chain[0].extensions.eku[_]
}
~~~

## "fulcio-issuer" policy

~~~abnf
policy-name   = "fulcio-issuer"
policy-value  = fulcio-issuer
fulcio-issuer = 1*idchar
~~~

`fulcio-issuer` is `chain[0].extensions.fulcio_issuer` without leading `https://`, percent-encoded.

Example:

`did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk::fulcio-issuer:accounts.google.com::san:email:bob%40example.com`

Example 2:

`did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk::fulcio-issuer:token.actions.githubusercontent.com::san:uri:https%3A%2F%2Fgithub.com%2Focto-org%2Focto-automation%2F.github%2Fworkflows%2Foidc.yml%40refs%2Fheads%2Fmain`

Rego policy:

~~~rego
validate_policy(name, value) := true if {
    name == "fulcio-issuer"
    suffix := urlquery.decode(value)
    concat("", ["https://", suffix]) == input.chain[0].extensions.fulcio_issuer
}
~~~

## DID resolution options

This DID method introduces a new DID resolution option called `x509chain`:

Name: `x509chain`

Value type: string

The value is constructed as follows:

1. Encode each certificate `C` that is part of the chain as the string `b64url(DER(C))`.
2. Concatenate the resulting strings in order, separated by comma `","`.

# CDDL for a JSON Data Model for X.509 Certification Paths

~~~ cddl
CertificateChain = [2*Certificate]  ; leaf is first

Certificate = {
    fingerprint: {
        ; base64url-encoded hashes of the DER-encoded certificate
        sha256: base64url,     ; FIPS 180-4, SHA-256
        sha384: base64url,     ; FIPS 180-4, SHA-384
        sha512: base64url      ; FIPS 180-4, SHA-512
    },
    issuer: Name,              ; RFC 5280, Section 4.1.2.4
    subject: Name,             ; RFC 5280, Section 4.1.2.6
    extensions: {
        ? eku: [+OID],         ; RFC 5280, Section 4.2.1.12
        ? san: [+SAN],         ; RFC 5280, Section 4.2.1.6
        ? fulcio_issuer: tstr  ; http://oid-info.com/get/1.3.6.1.4.1.57264.1.1
    }
}

; X.509 Name as an object of attributes
; Repeated attribute types are not supported
; Common attribute types have human-readable labels (see below)
; Other attribute types use dotted OIDs
; Values are converted to UTF-8
Name = {
    ; See RFC 4514, Section 3, for meaning of common attribute types
    ? CN: tstr,
    ? L: tstr,
    ? ST: tstr,
    ? O: tstr,
    ? OU: tstr,
    ? C: tstr,
    ? STREET: tstr,
    * OID => tstr
}

; base64url-encoded data, see RFC 4648, Section 5
base64url = tstr

; ASN.1 Object Identifier
; Dotted string, for example "1.2.3"
OID = tstr

; X.509 Subject Alternative Name
; Strings are converted to UTF-8
SAN = rfc822Name / DNSName / URI / DirectoryName
rfc822Name = ["email", tstr] ; Example: ["email", "bill@microsoft.com"]
DNSName = ["dns", tstr]      ; Example: ["dns", "microsoft.com"]
URI = ["uri", tstr]          ; Example: ["uri", "https://microsoft.com"]
DirectoryName = ["dn", Name] ; Example: ["dn", {CN: "Microsoft"}]
~~~
{: #fig-cddl-placeholder artwork-align="left"
   title="CDDL definition of did:x.509 JSON Data Model"}

# Privacy Considerations {#privconsec}

Some considerations

# Security Consideration {#secconsec}

### Identifier ambiguity

This DID method maps characteristics of X.509 certificate chains to identifiers. It allows a single identifier to map to multiple certificate chains, giving the identifier stability across the expiry of individual chains. However, if the policies used in the identifier are chosen too loosely, the identifier may match too wide a set of certificate chains. This may have security implications as it may authorize an identity for actions it was not meant to be authorized for.

To mitigate this issue, the certificate authority should publish their expected usage of certificate fields and indicate which ones constitute a unique identity, versus any additional fields that may be of an informational nature. This will help users create an appropriate did:x509 as well as consumers of signed content to decide whether it is appropriate to trust a given did:x509.

### X.509 trust stores

Typically, a verifier trusts an X.509 certificate by applying chain validation defined in {{Section 6 of RFC5280}} using a set of certificate authority (CA) certificates as trust store, together with additional application-specific policies.

This DID method does not require an X.509 trust anchor store but rather relies on verifiers either trusting an individual DID directly or using third-party endorsements for a given DID, like {{VC}}, to establish trust.

By layering this DID method on top of X.509, verifiers are free to use traditional chain validation (for example, verifiers unaware of DID), or rely on DID as an ecosystem to establish trust.

# IANA Considerations

[^rfced] Please replace "{{&SELF}}" with the RFC number assigned to this document.

[^rfced] Some considerations

--- back

# Acknowledgments
{:numbered="false"}

The authors would like to thank
_list_
for their reviews and suggestions.

[^rfced]: RFC Editor:
