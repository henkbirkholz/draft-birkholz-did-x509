---
v: 3

title: "Decentralized Identifiers (DID) Method did:x509"
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
  RFC5280:
  VC:
    target: https://www.w3.org/TR/vc-data-model/
    title: W3C Verifiable Credentials

informative:
  I-D.ietf-scitt-architechture: scitt-arch

entity:
  SELF: "RFCthis"

--- abstract

Some abstract

--- middle

# Introduction

Some intro

# Conventions and Definitions

{::boilerplate bcp14-tagged}

In this document, CDDL {{-cddl}} {{-cddlplus}} is used to describe the
data formats.

The reader is assumed to be familiar with the vocabulary and concepts
defined in {{-scitt-arch}}.

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
