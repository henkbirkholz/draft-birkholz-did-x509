---
v: 3

title: "Decentralized Identifiers (DID) Method did:509"
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

informative:
  I-D.ietf-scitt-architechture: scitt-arch
  RFC9360:
  RFC9597:

entity:
  SELF: "RFCthis"

--- abstract

Some abstract

--- middle

# Introduction

This draft aims to define an interoperable and flexible issuer identifier format for COSE messages that transport or refer to X.509 certificates using {{RFC9360}}.
The did:x509 identifier format implements a direct, resolvable binding between a certificate chain and a compact issuer string.
It can be used in a COSE Header CWT Claims map as defined in {{RFC9597}}.
This issuer identifier is convenient for references and policy evaluation, for example in the context of transparency ledgers. 

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
