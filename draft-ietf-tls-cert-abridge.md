---
title: "Abridged Compression for WebPKI Certificates"
abbrev: "Abridged Certs"
category: exp

docname: draft-ietf-tls-cert-abridge-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "Transport Layer Security"

venue:
  group: "Transport Layer Security"
  type: "Working Group"
  mail: "tls@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/tls/"
  github: "tlswg/draft-ietf-tls-cert-abridge"
  latest: "https://tlswg.github.io/draft-ietf-tls-cert-abridge/draft-ietf-tls-cert-abridge.html"

author:
 -
    fullname: Dennis Jackson
    organization: Mozilla
    email: ietf@dennis-jackson.uk

normative:
 TLSCertCompress: RFC8879
 BROTLI: RFC7932
 TLS13: RFC8446
 DATES: RFC3339

 AppleCTLogs:
   title: Certificate Transparency Logs trusted by Apple
   target: https://valid.apple.com/ct/log_list/current_log_list.json
   date: 2023-06-05
   author:
    -
      org: "Apple"

 GoogleCTLogs:
   title: Certificate Transparency Logs trusted by Google
   target: https://source.chromium.org/chromium/chromium/src/+/main:components/certificate_transparency/data/log_list.json
   date: 2023-06-05
   author:
    -
      org: "Google"

 CCADBAllCerts:
   title: CCADB Certificates Listing
   target: https://ccadb.my.salesforce-sites.com/ccadb/AllCertificateRecordsCSVFormat
   date: 2023-06-05
   author:
    -
      org: "Mozilla"
    -
      org: "Microsoft"
    -
      org: "Google"
    -
      org: "Apple"
    -
      org: "Cisco"

informative:
 RFC9000:
 SCA: I-D.kampanakis-tls-scas-latest
 ECH: I-D.draft-ietf-tls-esni-17

 FastlyStudy:
   title: Does the QUIC handshake require compression to be fast?
   target: https://www.fastly.com/blog/quic-handshake-tls-compression-certificates-extension-study
   date: 2020-05-18
   author:
    -
      ins: "P. McManus"
      name: "Patrick McManus"
      org: "Fastly"

 QUICStudy: DOI.10.1145/3555050.3569123
 SCAStudy: DOI.10.1007/978-3-031-07689-3_25

 PQStudy:
   title: Sizing Up Post-Quantum Signatures
   target: https://blog.cloudflare.com/sizing-up-post-quantum-signatures/
   date: 2021-11-08
   author:
    -
      name: Bas Westerbaan
      ins: B. Westerbaan
      org: "Cloudflare"

 CCADB:
   title: Common CA Database
   target: https://www.ccadb.org/
   date: 2023-06-05
   author:
    -
      org: "Mozilla"
    -
      org: "Microsoft"
    -
      org: "Google"
    -
      org: "Apple"
    -
      org: "Cisco"

 FingerprintingPost:
   title: "The state of TLS fingerprinting What’s Working, What Isn’t, and What’s Next"
   target: https://www.fastly.com/blog/the-state-of-tls-fingerprinting-whats-working-what-isnt-and-whats-next
   date: 2022-07-20
   author:
    -
      name: "Fastly Security Research Team"
      org: "Fastly"

--- abstract

This draft defines a new TLS Certificate Compression scheme which uses a shared dictionary of root and intermediate WebPKI certificates. The scheme smooths the transition to post-quantum certificates by eliminating the root and intermediate certificates from the TLS certificate chain without impacting trust negotiation. It also delivers better compression than alternative proposals whilst ensuring fair treatment for both CAs and website operators. It may also be useful in other applications which store certificate chains, e.g. Certificate Transparency logs.

--- middle

# Introduction

## Motivation

When a server responds to a TLS Client Hello, the size of its initial flight of packets is limited by the underlying transport protocol. If the size limit is exceeded, the server must wait for the client to acknowledge receipt before concluding the flight, incurring the additional latency of a round trip before the handshake can complete. For TLS handshakes over TCP, the size limit is typically around 14,500 bytes. For TLS handshakes in QUIC, the limit is much lower at a maximum of 4500 bytes ({{RFC9000, Section 8.1}}).

The existing compression schemes used in {{TLSCertCompress}} have been shown to deliver a substantial improvement in QUIC handshake latency {{FastlyStudy}}, {{QUICStudy}} by reducing the size of server's certificate chain and so fitting the server's initial messages within a single flight. However, in a post-quantum setting, the signatures and public keys used in a TLS certificate chain will be typically 10 to 40 times their current size and cannot be compressed with existing TLS Certificate Compression schemes because most of the size of the certificate is in high entropy fields such as cryptographic keys and signatures.

Consequently studies {{SCAStudy}} {{PQStudy}} have shown that post-quantum certificate transmission becomes the dominant source of latency in PQ TLS with certificate chains alone expected to exceed even the TCP initial flight limit. This motivates alternative designs for reducing the wire size of post-quantum certificate chains.

## Overview

This draft introduces a new TLS certificate compression scheme which is intended specifically for WebPKI applications and is negotiated using the existing certificate compression extension described in {{TLSCertCompress}}. It uses a predistributed dictionary consisting of all intermediate and root certificates contained in the root stores of major browsers which is sourced from the Common CA Database {{CCADB}}. As of May 2023, this dictionary would be 3 MB in size and consist of roughly 2000 intermediate certificates and 200 root certificates. The disk footprint can be reduced to near zero as many clients (such as Mozilla Firefox & Google Chrome) are already provisioned with their trusted intermediate and root certificates for compatibility and performance reasons.

Using a shared dictionary allows for this compression scheme to deliver dramatically more effective compression than previous schemes, reducing the size of certificate chains in use today by ~75%, significantly improving on the ~25% reduction achieved by existing schemes. A preliminary evaluation ({{eval}}) of this scheme suggests that 50% of certificate chains in use today would be compressed to under 1000 bytes and 95% to under 1500 bytes. Similarly to {{SCA}}, this scheme effectively removes the CA certificates from the certificate chain on the wire but this draft achieves a much better compression ratio, since {{SCA}} removes the redundant information in chain that existing TLS Certificate Compression schemes exploit and is more fragile in the presence of out of sync clients or servers.

Note that as this is only a compression scheme, it does not impact any trust decisions in the TLS handshake. A client can offer this compression scheme whilst only trusting a subset of the certificates in the CCADB certificate listing, similarly a server can offer this compression scheme whilst using a certificate chain which does not chain back to a WebPKI root. Furthermore, new root certificates are typically included in the CCADB at the start of their application to a root store, a process which typically takes more than a year. Consequently, applicant root certificates can be added to new versions of this scheme ahead of any trust decisions, allowing new CAs to compete on equal terms with existing CAs as soon as they are approved for inclusion in a root program. As a result this scheme is equitable in so far as it provides equal benefits for all CAs in the WebPKI, doesn't privilege any particular end-entity certificate or website and allows WebPKI clients to make individual trust decisions without fear of breakage.

## Relationship to other drafts

This draft defines a certificate compression mechanism suitable for use with TLS Certificate Compression {{TLSCertCompress}}.

The intent of this draft is to provide an alternative to CA Certificate Suppression {{SCA}} as it provides a better compression ratio, can operate in a wider range of scenarios (including out of sync clients or servers) and doesn't require any additional error handling or retry mechanisms.

CBOR Encoded X.509 (C509) {{?I-D.ietf-cose-cbor-encoded-cert-05}} defines a concise alternative format for X.509 certificates. If this format were to become widely used on the WebPKI, defining an alternative version of this draft specifically for C509 certificates would be beneficial.

Compact TLS, (cTLS) {{?I-D.ietf-tls-ctls-08}} defines a version of TLS1.3 which allows a pre-configured client and server to establish a session with minimal overhead on the wire. In particular, it supports the use of a predefined list of certificates known to both parties which can be compressed. However, cTLS is still at an early stage and may be challenging to deploy in a WebPKI context due to the need for clients and servers to have prior knowledge of handshake profile in use.

TLS Cached Information Extension {{?RFC7924}} introduced a new extension allowing clients to signal they had cached certificate information from a previous connection and for servers to signal that the clients should use that cache instead of transmitting a redundant set of certificates. However this RFC has seen little adoption in the wild due to concerns over client privacy.

Handling long certificate chains in TLS-Based EAP Methods {{?RFC9191}} discusses the challenges of long certificate chains outside the WebPKI ecosystem. Although the scheme proposed in this draft is targeted at WebPKI use, defining alternative shared dictionaries for other major ecosystems may be of interest.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

This draft refers to dates in Internet Date/Time Format as specified in {{Section 5.6 of DATES}} without the optional `T` separator.

# Abridged Compression Scheme {#scheme}

This section describes a compression scheme suitable for compressing certificate chains used in TLS. The scheme is defined in two parts. An initial pass compressing known intermediate and root certificates and then a subsequent pass compressing the end-entity certificate.

The compression scheme in this draft has one parameter listed below which influence the construction of the static dictionary. Future versions of this draft would use different parameters and so construct different dictionaries which would be registered under different TLS Certificate Compression code points. This is discussed further in {{deployment}}.

* `CCADB_SNAPSHOT_TIME` - `2023-01-01 00:00:00Z`

## Pass 1: Intermediate and Root Compression

This pass relies on a shared listing of intermediate and root certificates known to both client and server. As many clients (e.g. Mozilla Firefox and Google Chrome) already ship with a list of trusted intermediate and root certificates, this pass allows their existing lists to be reused, rather than requiring them to have to be duplicated and stored in a separate format. The first subsection details how the certificates are enumerated in an ordered list. This ordered list is distributed to client and servers which use it to compress and decompress certificate chains as detailed in the subsequent subsection.

### Enumeration of Known Intermediate and Root Certificates {#listing}

The Common CA Database {{CCADB}} is operated by Mozilla on behalf of a number of Root Program operators including Mozilla, Microsoft, Google, Apple and Cisco. The CCADB contains a listing of all the root certificates trusted by these root programs, as well as their associated intermediate certificates and not yet trusted certificates from new applicants to one or more root programs.

At the time of writing, the CCADB contains around 200 root program certificates and 2000 intermediate certificates which are trusted for TLS Server Authentication, occupying 3 MB of disk space. The listing used in this draft will be the relevant certificates included in the CCADB at `CCADB_SNAPSHOT_TIME`.

As entries on this list typically have a lifespan of 10+ years and new certificates are added to the CCADB a year or or more before being marked as trusted, future drafts which include newer certificates will only need to be issued infrequently. This is discussed further in {{deployment}}.

The algorithm for enumerating the list of compressible intermediate and root certificates is given below:

1. Query the CCADB for all known root and intermediate certificates {{CCADBAllCerts}} as of `CCADB_SNAPSHOT_TIME`
2. Remove all certificates which have an extendedKeyUsage extension but do not have the TLS Server Authentication bit set or the anyExtendedKeyUsage bit set.
3. Remove all certificates whose notAfter date is on or before `CCADB_SNAPSHOT_TIME`.
4. Remove all root certificates which are not marked as trusted or in the process of applying to be trusted by at least one of the following browser root programs: Mozilla, Google, Microsoft, Apple.
5. Remove all intermediate certificates which do not chain back to root certificates still in the listing.
6. Remove any certificates which are duplicates (have the same SHA256 certificate fingerprint)
7. Order the list of certificates by the timestamp for when each was added to the CCADB, breaking any ties with the lexicographic ordering of the SHA256 certificate fingerprint.
8. Associate each element of the list with the concatenation of the constant `0xff` and its index in the list represented as a `uint16`.

The URL for this list and a copy of the listing is included in {{ccadblist}}.

### Compression of CA Certificates in Certificate Chain

Compression Algorithm:

* Input: The byte representation of a `Certificate` message as defined in {{TLS13}} whose contents are `X509` certificates.
* Output: `opaque` bytes suitable for transmission in a `CompressedCertificate` message defined in {{TLSCertCompress}}.

1. Parse the message and extract a list of `CertificateEntry`s, iterate over the list.
2. Check if `cert_data` is bitwise identical to any of the known intermediate or root certificates from the listing in the previous section.
   1. If so, replace the opaque `cert_data` member of `CertificateEntry` with its adjusted three byte identifier and copy the `CertificateEntry` structure with corrected lengths to the output.
   2. Otherwise, copy the `CertificateEntry` entry to the output without modification.
3. Correct the length field for the `Certificate` message.

The resulting output should be a well-formatted `Certificate` message payload with the recognized intermediate and root certificates replaced with three byte identifiers and resulting lengths corrected. Note that the `extensions` field in each `CertificateEntry` remains unchanged, as does the `certificate_request_context` and any unrecognized certificates.

The decompression algorithm requires the above steps but in reverse, swapping any recognized three-byte identifier in a `cert_data` field with the DER representation of the associated certificate and updating the lengths.

If the compressed certificate chain cannot be parsed (e.g. due to incorrect length fields) the decompression algorithm MUST report the failure to the TLS library. Any unrecognized three-byte identifiers encountered during decompression MUST also be treated as decompression failures. As required by {{TLSCertCompress}}, decompression failures mean that the connection MUST be terminated with the "bad_certificate" alert.

TLS implementations intending to only use this scheme as a compressor (e.g. servers) SHOULD minimize the storage requirements of pass 1 by using a lookup table which maps the cryptographic hash of each certificate in the pass 1 listing to its assigned three byte identifier. This avoids the need for the compressor to retain a full copy of the pass 1 list. The hashing algorithm used in this lookup table is internal to the implementation and not exposed, but MUST be cryptographically secure. Note that implementations using this scheme as a decompressor (e.g. clients) typically already ship with a listing of trusted root and intermediate certificates which can be reused by the decompressor without any additional storage overhead.

## Pass 2: End-Entity Compression

The second pass uses Brotli {{BROTLI}} to compress any redundant data in the end-entity certificate. Benchmarks on existing certificate chains suggest that the compression ratio is relatively insensitive to the compressor's parameters.  It is RECOMMENDED that the compressor (i.e. the server) use the following parameters:

 * `quality=5`
 * `lgwindow=17`

Benchmarks on real world certificate chains suggest that higher values require greater CPU usage but do not result in better compression.

# Evaluation {#eval}

[[**NOTE:** This section to be removed prior to publication.]]

The columns report the 5th, 50th and 95th percentile of the resulting certificate chains wire sizes in bytes. The evaluation set was ~75000 certificate chains from the Tranco list using the python scripts in the draft's Github repository.

| Scheme                                               |   p5 |   p50 |   p95 |
|------------------------------------------------------|------|-------|-------|
| Original / Uncompressed                              | 2308 |  4032 |  5609 |
| Existing TLS Certificate Compression                 | 1619 |  3243 |  3821 |
| **This Draft**                                       |  881 |  1256 |  1716 |
| Hypothetical Optimal Compression                     |  377 |   742 |  1075 |

 * 'Original' refers to the sampled certificate chains without any compression.
 * 'TLS Cert Compression' used ZStandard with the parameters configured for maximum compression as defined in {{TLSCertCompress}}.
 * 'Hypothetical Optimal Compression' is the resulting size of the cert chain after reducing it to only the public key in the end-entity certificate, the CA signature over the EE cert, the embedded SCT signatures and a compressed list of domains in the SAN extension. This represents the best possible compression as it entirely removes any CA certs, identifiers, field tags and lengths and non-critical extensions such as OCSP, CRL and policy extensions.

# Deployment Considerations {#deployment}

## Dictionary Versioning

The scheme defined in this draft is deployed with the static dictionaries constructed from the parameters listed in {{scheme}} fixed to a particular TLS Certificate Compression code point.

As new CA certificates are added to the CCADB and deployed on the web, new versions of this draft would need to be issued with their own code point and dictionary parameters. However, the process of adding new root certificates to a root store is already a two to three year process and this scheme includes untrusted root certificates still undergoing the application process in its dictionary. As a result, it would be reasonable to expect a new version of this scheme with updated dictionaries to be issued at most once a year and more likely once every two or three years.

A more detailed analysis and discussion of CA certificate lifetimes and root store operations is included in {{churn}}, as well as an alternative design which would allow for dictionary negotiation rather than fixing one dictionary per code point.

## Version Migration

As new versions of this scheme are specified, clients and servers would benefit from migrating to the latest version. Whilst servers using CA certificates outside the scheme's listing can still offer this compression scheme and partially benefit from it, migrating to the latest version ensures that new CAs can compete on a level playing field with existing CAs. It is possible for a client or server to offer multiple versions of this scheme without having to pay twice the storage cost, since the majority of the stored data is in the pass 1 certificate listing and the majority of certificates will be in both versions and so need only be stored once.

Clients and servers SHOULD offer the latest version of this scheme and MAY offer one or more historical versions. Although clients and servers which fall out of date will no longer benefit from the scheme, they will not suffer any other penalties or incompatibilities. Future schemes will likely establish recommended lifetimes for sunsetting a previous version and adopting a new one.

As the majority of clients deploying this scheme are likely to be web browsers which typically use monthly release cycles (even long term support versions like Firefox ESR offer point releases on a monthly basis), this is unlikely to be a restriction in practice. The picture is more complex for servers as operators are often to reluctant to update TLS libraries, but as a new version only requires changes to static data without any new code and would happen infrequently, this is unlikely to be burdensome in practice.

## Disk Space Requirements

Clients and servers implementing this scheme need to store a listing of root and intermediate certificates for pass 1, which currently occupies around ~3 MB and a smaller dictionary on the order of ~100 KB for pass 2. Clients and servers offering multiple versions of this scheme do not need to duplicate the pass 1 listing, as multiple versions can refer to same string.

As popular web browsers already ship a complete list of trusted intermediate and root certificates, their additional storage requirements are minimal. Servers offering this scheme for their own certificate chain do not need to store the list of pass 1 root and intermediate certificates at all. Instead, they can store the hash of each certificate in the dictionary and its associated identifier, which reduces their storage footprint to ~60 KB. It is also permissible for servers only performing compression to only store a subset of the full pass 1 dictionary, as it is not an error for a server to choose not to compress a particular entry.

## Implementation Complexity

Although much of this draft is dedicated to the construction of the certificate list and dictionary used in the scheme, implementations are indifferent to these details. Pass 1 can be implemented as a simple string substitution and pass 2 with already widely deployed functionality for Brotli Certificate Compression. Future versions of this draft which vary the dictionary construction then only require changes to the static data shipped with these implementations and the use of a new code point.

There are several options for handling the distribution of the associated static data. One option is to distribute it directly with the TLS library and update it as part of that library's regular release cycle. Whilst this is easy for statically linked libraries written in languages which offer first-class package management and compile time feature selection (e.g. Go, Rust), it is trickier for dynamically linked libraries who are unlikely to want to incur the increased distribution size. In these ecosystems it may make sense to distribute the dictionaries are part of an independent package managed by the OS which can be discovered by the library at run-time. Another promising alternative would be to have existing automated certificate tooling provision the library with both the full certificate chain and multiple precompressed chains during the certificate issuance / renewal process.

# Security Considerations

This draft does not introduce new security considerations for TLS, except for the considerations already identified in {{TLSCertCompress}}, in particular:

* The decompressed Certificate message MUST be processed as if it were encoded without being compressed in order to ensure parsing and verification have the same security properties as they would in TLS normally.
* Since Certificate chains are presented on a per-server-name or per-user basis, a malicious application cannot introduce individual fragments into the Certificate message in order to leak information by modifying the plaintext.

Further, implementors SHOULD use a memory-safe language to implement this compression schemes.

Note that as this draft specifies a compression scheme, it does not impact the negotiation of trust between clients and servers and is robust in the face of changes to CCADB or trust in a particular WebPKI CA. The client's trusted list of CAs does not need to be a subset or superset of the CCADB list and revocation of trust in a CA does not impact the operation of this compression scheme. Similarly, servers who use roots or intermediates outside the CCADB can still offer and benefit from this scheme.

# Privacy Considerations

Some servers may attempt to identify clients based on their TLS configuration, known as TLS fingerprinting {{FingerprintingPost}}. If there is significant diversity in the number of TLS Certificate Compression schemes supported by clients, this might enable more powerful fingerprinting attacks. However, this compression scheme can be used by a wide range of clients, even if they make different or contradictory trust decisions and so the resulting diversity is expected to be low.

In TLS1.3, the extension carrying the client's supported TLS Certificate Compression schemes is typically transmitted unencrypted and so can also be exploited by passive network observers in addition to the server with whom the client is communicating. Deploying Encrypted Client Hello {{ECH}} enables the encryption of the Client Hello and the TLS Certificate Compression extension within it which can mitigate this leakage.

# IANA Considerations

This draft uses the TLS Certificate Compression Algorithm ID 43776 (0xab00) which is available under the Experimental Use policy and does not require any IANA actions.

--- back

# Acknowledgments

The authors thank Bas Westerbaan, Peter Wu, Ilari Liusvaara, Martin Thomson and Kathleen Wilson for feedback and helpful discussions on this document.

# CCADB Churn and Dictionary Negotiation {#churn}

## CCADB Churn

Typically around 10 or so new root certificates are introduced to the WebPKI each year. The various root programs restrict the lifetimes of these certificates, Microsoft to between 8 and 25 years ([3.A.3](https://learn.microsoft.com/en-us/security/trusted-root/program-requirements)), Mozilla to between 0 and 14 years ([Summary](https://wiki.mozilla.org/CA/Root_CA_Lifecycles)). Chrome has proposed a maximum lifetime of 7 years in the future ([Blog Post](https://www.chromium.org/Home/chromium-security/root-ca-policy/moving-forward-together/)). Some major CAs have objected to this proposed policy as the root inclusion process currently takes around 3 years from start to finish ([Digicert Blog](https://www.digicert.com/blog/googles-moving-forward-together-proposals-for-root-ca-policy)). Similarly, Mozilla requires CAs to apply to renew their roots with at least 2 years notice ([Summary](https://wiki.mozilla.org/CA/Root_CA_Lifecycles)).

Typically around 100 to 200 new WebPKI intermediate certificates are issued each year. No WebPKI root program currently limits the lifetime of intermediate certificates, but they are in practice capped by the lifetime of their parent root certificate. The vast majority of these certificates are issued with 10 year lifespans. A small but notable fraction (<10%) are issued with 2 or 3 year lifetimes. Chrome's Root Program has proposed that Intermediate Certificates be limited to 3 years in the future ([Update](https://www.chromium.org/Home/chromium-security/root-ca-policy/moving-forward-together/)). However, the motivation for this requirement is unclear. Unlike root certificates, intermediate certificates are only required to be disclosed with a month's notice to the CCADB ([Mozilla Root Program Section 5.3.2](https://www.mozilla.org/en-US/about/governance/policies/security-group/certs/policy/#53-intermediate-certificates), [Chrome Policy](https://www.chromium.org/Home/chromium-security/root-ca-policy/)).

## Dictionary Negotiation

This draft is currently written with a view to being adopted as a particular TLS Certificate Compression Scheme. However, this means that each dictionary used in the wild must have an assigned code point. A new dictionary would likely need to be issued no more than yearly. However, negotiating the dictionary used would avoid the overhead of minting a new draft and code point. A sketch for how dictionary negotiation might work is below.

This draft would instead define a new extension, which would define TLS Certificate Compression with Preshared Dictionaries. Dictionaries would be identified by an IANA-assigned identifier of two bytes, with a further two bytes for the major version and two more for the minor version. Adding new certificates to a dictionary listing would require a minor version bump. Removing certificates or changing the pass 2 dictionary would require a major version bump.

~~~
struct {
  uint16 identifier;
  uint16 major_version;
  uint16 minor_version;
} DictionaryId
~~~

The client lists their known dictionaries in an extension in the ClientHello. The client need only retain and advertise the highest known minor version for any major version of a dictionary they are willing to offer. The server may select any dictionary it has a copy of with matching identifier, matching major version number and a minor version number not greater than the client's minor version number.

The expectation would be that new minor versions would be issued monthly or quarterly, with new major versions only every year or multiple years. This reflects the relative rates of when certificates are added or removed to the CCADB listing. This means in practice clients would likely offer a single dictionary containing their latest known version. Servers would only need to update their dictionaries yearly when a new major version is produced.

# Pass 1 Dictionary {#ccadblist}

The Pass 1 Dictionary is available from the CCADB at the following url:

`https://ccadb.my.salesforce-sites.com/ccadb/WebTrustListAsOf?ListDate={DATE}`

Where the parameter `DATE` can be left empty (to fetch the current list) or be passed a date in the format `YYYY-MM-DD`. The resulting file is CSV-formatted and contains the X.509 Certificate PEM for each entry. This draft uses the date 2024-01-01.

Below is a listing which maps the three byte identifier of each certificate to the SHA-256 of the certificate in DER format (i.e. as it would appear on the wire in a TLS Certificate Message).

```
ff0000:d7a7a0fb5d7e2731d771e9484ebcdef71d5f0c3e0a2948782bc83ee0ea699ef4
ff0001:9a6ec012e1a7da9dbe34194d478ad7c0db1822fb071df12981496ed104384113
ff0002:55926084ec963a64b96e2abe01ce0ba86a64fbfebcc7aab5afc155b37fd76066
ff0003:0376ab1d54c5f9803ce4b2e201a0ee7eef7b57b636e8a93c9b8d4860c96f5fa7
ff0004:0a81ec5a929777f145904af38d5d509f66b5e2c58fcdb531058b0e17f3f0b41b
ff0005:70a73f7f376b60074248904534b11482d5bf0e698ecc498df52577ebf2e93b9a
ff0006:bd71fdf6da97e4cf62d1647add2581b07d79adf8397eb4ecba9c5e8488821423
ff0007:f356bea244b7a91eb35d53ca9ad7864ace018e2d35d5f8f96ddf68a6f41aa474
ff0008:04048028bf1f2864d48f9ad4d83294366a828856553f3b14303f90147f5d40ef
ff0009:16af57a9f676b0ab126095aa5ebadef22ab31119d644ac95cd4b93dbf3f26aeb
ff000a:9a114025197c5bb95d94e63d55cd43790847b646b23cdf11ada4a00eff15fb48
ff000b:edf7ebbca27a2a384d387b7d4010c666e2edb4843e4c29b4ae1d5b9332e6b24d
ff000c:e23d4a036d7b70e9f595b1422079d2b91edfbb1fb651a0633eaa8a9dc5f80703
ff000d:e3b6a2db2ed7ce48842f7ac53241c7b71d54144bfb40c11f3f1d0b42f5eea12d
ff000e:eaa962c4fa4a6bafebe415196d351ccd888d4f53f3fa8ae6d7c466a94e6042bb
ff000f:5c58468d55f58e497e743982d2b50010b6d165374acf83a7d4a32db768c4408e
ff0010:0c2cd63df7806fa399ede809116b575bf87989f06518f9808c860503178baf66
ff0011:1793927a0614549789adce2f8f34f7f0b66d0f3ae3a3b84d21ec15dbba4fadc7
ff0012:3e9099b5015e8f486c00bcea9d111ee721faba355a89bcf1df69561e3dc6325c
ff0013:7d05ebb682339f8c9451ee094eebfefa7953a114edb2f44949452fab7d2fc185
ff0014:7e37cb8b4c47090cab36551ba6f45db840680fba166a952db100717f43053fc2
ff0015:4348a0e9444c78cb265e058d5e8944b4d84f9662bd26db257f8934a443c70161
ff0016:cb3ccbb76031e5e0138f8dd39a23f9de47ffc35e43c1144cea27d46a5ab1cb5f
ff0017:31ad6648f8104138c738f39ea4320133393e3a18cc02296ef97c2ac9ef6731d0
ff0018:7431e5f4c3c1ce4690774f0b61e05440883ba9a01ed00ba6abd7806ed3b118cf
ff0019:552f7bdcf1a7af9e6ce672017f4f12abf77240c78e761ac203d1d9d20ac89988
ff001a:49e7a442acf0ea6287050054b52564b650e4f49e42e348d6aa38e039e957b1c1
ff001b:eec5496b988ce98625b934092eec2908bed0b0f316c2d4730c84eaf1f3d34881
ff001c:73c176434f1bc6d5adf45b0e76e727287c8de57616c1e6e6141a2b2cbc7d8e4c
ff001d:6dc47172e01cbcb0bf62580d895fe2b8ac9ad4f873801e0c10b9c837d21eb177
ff001e:c0a6f4dc63a24bfdcf54ef2a6a082a0a72de35803e2ff5ff527ae5d87206dfd5
ff001f:cbb522d7b7f127ad6a0113865bdf1cd4102e7d0759af635a7cf4720dc963c53b
ff0020:ebd41040e4bb3ec742c9e381d31ef2a41a48b6685c96e7cef3c1df6cd4331c99
ff0021:c3846bf24b9e93ca64274c0ec67c1ecc5e024ffcacd2d74019350e81fe546ae4
ff0022:45140b3247eb9cc8c5b4f0d7b53091f73292089e6e5a63e2749dd3aca9198eda
ff0023:bc104f15a48be709dca542a7e1d4b9df6f054527e802eaa92d595444258afe71
ff0024:2530cc8e98321502bad96f9b1fba1b099e2d299e0f4548bb914f363bc0d4531f
ff0025:3c5f81fea5fab82c64bfa2eaecafcde8e077fc8620a7cae537163df36edbf378
ff0026:6c61dac3a2def031506be036d2a6fe401994fbd13df9c8d466599274c446ec98
ff0027:8a866fd1b276b57e578e921c65828a2bed58e9f2f288054134b7f1f4bfc9cc74
ff0028:85a0dd7dd720adb7ff05f83d542b209dc7ff4528f7d677b18389fea5e5c49e86
ff0029:8fe4fb0af93a4d0d67db0bebb23e37c71bf325dcbcdd240ea04daf58b47e1840
ff002a:18f1fc7f205df8adddeb7fe007dd57e3af375a9c4d8d73546bf4f1fed1e18d35
ff002b:88ef81de202eb018452e43f864725cea5fbd1fc2d9d205730709c5d8b8690f46
ff002c:4200f5043ac8590ebb527d209ed1503029fbcbd41ca1b506ec27f15ade7dac69
ff002d:bf0feefb9e3a581ad5f9e9db7589985743d261085c4d314f6f5d7259aa421612
ff002e:f1c1b50ae5a20dd8030ec9f6bc24823dd367b5255759b4e71b61fce9f7375d73
ff002f:513b2cecb810d4cde5dd85391adfc6c2dd60d87bb736d2b521484aa47a0ebef6
ff0030:1465fa205397b876faa6f0a9958e5590e40fcc7faa4fb7c2c8677521fb5fb658
ff0031:2ce1cb0bf9d2f9e102993fbe215152c3b2dd0cabde1c68e5319b839154dbb7f5
ff0032:568d6905a2c88708a4b3025190edcfedb1974a606a13c6e5290fcb2ae63edab5
ff0033:62dd0be9b9f50a163ea0f8e75c053b1eca57ea55c8688f647c6881f2c8357b95
ff0034:be6c4da2bbb9ba59b6f3939768374246c3c005993fa98f020d1dedbed48a81d5
ff0035:dd6936fe21f8f077c123a1a521c12224f72255b73e03a7260693e8a24b0fa389
ff0036:91e2f5788d5810eba7ba58737de1548a8ecacd014598bc0b143e041b17052552
ff0037:fd73dad31c644ff1b43bef0ccdda96710b9cd9875eca7e31707af3e96d522bbd
ff0038:59769007f7685d0fcd50872f9f95d5755a5b2b457d81f3692b610a98672f0e1b
ff0039:bfd88fe1101c41ae3e801bf8be56350ee9bad1a6b9bd515edc5c6d5b8711ac44
ff003a:cecddc905099d8dadfc5b1d209b737cbe2c18cfb2c10c0ff0bcf0d3286fc1aa2
ff003b:52f0e1c4e58ec629291b60317f074671b85d7ea80d5b07273463534b32b40234
ff003c:e793c9b02fd8aa13e21c31228accb08119643b749c898964b1746d46c3d4cbd2
ff003d:4ff460d54b9c86dabfbcfc5712e0400d2bed3fbc4d4fbdaa86e06adcd2a9ad7a
ff003e:bec94911c2955676db6c0a550986d76e3ba005667c442c9762b4fbb773de228c
ff003f:179fbc148a3dd00fd24ea13458cc43bfa7f59c8182d783a513f6ebec100c8924
ff0040:5d56499be4d2e08bcfcad08a3e38723d50503bde706948e42f55603019e528ae
ff0041:30d0895a9a448a262091635522d1f52010b5867acae12c78ef958fd4f4389f2f
ff0042:5cc3d78e4e1d5e45547a04e6873e64f90cf9536d1ccc2ef800f355c4c5fd70fd
ff0043:43df5774b03e7fef5fe40d931a7bedf1bb2e6b42738c4e6d3841103d3aa7f339
ff0044:02ed0eb28c14da45165c566791700d6451d7fb56f0b2ab1d3b8eb070e56edff5
ff0045:f7541cf69d1de1ac953abc1fad6f7807a34edfe9e12c11e66a195930c23ad6c6
ff0046:403e062a2653059113285baf80a0d4ae422c848c9f78fad01fc94bc5b87fef1a
ff0047:b0935dc04b4e60c0c42def7ec57a1b1d8f958d17988e71cc80a8cf5e635ba5b4
ff0048:6ac159b4c2bc8e729f3b84642ef1286bcc80d775fe278c740ada468d59439025
ff0049:2a99f5bc1174b73cbb1d620884e01c34e51ccb3978da125f0e33268883bf4158
ff004a:24e9f20ac167bb8f09de8a1e9968cc53f0b5f3a4948f51b8647b40b186c75ebe
ff004b:54837ef7b5ac4aa23606a15ef30de46e9bb7e23e60f6ed4f2612092b94edc68f
ff004c:438f473ebfc8884ef5d3e0d52d264cdbe56ca382d9ebfc689d77489409f55a6e
ff004d:dd4e0c17900f3fc2a5b7b773ae40218ad73216b5ce5d285ebffce8830d0f034a
ff004e:c123f5afacc9f9096809850355e5bf78ca9377348111b5167a964ddedc044de9
ff004f:beb8efe9b1a73c841b375a90e5fff8048848e3a2af66f6c4dd7b938d6fe8c5d8
ff0050:c9d6913f3feddeff184c9ee1d7e17c5aec90886eed5cc3d6e98105831c8c0e0b
ff0051:fda947208bfa3203a6c57b8714a647b7009e5168e88951345450b1d2d3f91a7d
ff0052:e1be6bbbb70f5a241e736fc44c6a2160bf6ce19b95edd67bf7be896e83778745
ff0053:28cbb4e0d9c4ee6d04ac8f14717605ae3a4bd8cbf8d081b27af6edb2f3d76a32
ff0054:1e0a3ab993157717281d42abf801eb64deed500e4168ca706d6a71d8103c73a2
ff0055:4c56ca7a3c10eb58765e0ffcf8035c57c9f3bdb014862f676756cf789193f10e
ff0056:48a7c9c5a36734fc9e204d63ce6bbbcd9e21c1978604760cd8d30d6f4c67b67c
ff0057:253e3c9732df8874c3d54da522c1711142c98c2cea7664635152a89a03ee9364
ff0058:b7dfdc27e5ff9f35efec9f4bc532c35f727789b69c90a0489b40247299d97038
ff0059:8fac576439c9fd3ef153b51f9edd0d381b5df7b87559cebeca04297dd44a639b
ff005a:93c381cb07b353a920c2a7bed6bebf195c68279dd0527d37f20bdd0d99c330fa
ff005b:634fdf26c994e76a2918d9efc4cab9c6fcb344ef642a79c89192bcda0ed52f4c
ff005c:19400be5b7a31fb733917700789d2f0a2471c0c9d506c0e504c06c16d7cb17c0
ff005d:6075da5cecd15d6584c5560322d5c09fc2199e52dea7921d91040aa75248672e
ff005e:0a163600631bd66267fb7aead25c538b2b7d72ad6416a2bbd285f654bb642f6d
ff005f:50d3d71fc0cd7e36adae32221fefbe8cc29b2676ba326c09b8fa1b24dbe75514
ff0060:be6a0d9e1d115f2293f6abf11b3ec8e882e24426eeeb09aaa503597993e77a25
ff0061:2f6889961a7ca7067e8ba103c2cf9b9a924f8ca293f11178e23a1978d2f133d3
ff0062:963056b0d941d9dbe27ac778053d85e43cc79f476ad34cfdd799c27e381840eb
ff0063:6e8d952fdbabad8de3d61e094393739b5a47371a52bdcb2a3c2f8c43622f640f
ff0064:d46931e0182dd655ea0c16e6dd99f8e61affe401f734c6ca8ea0056a968eaf81
ff0065:bf1cb0e213d8d3c70bae89429fc16de2c74f755963d1b9b488bd0260dbc91b9c
ff0066:91408a7183fd34ca493a88de74e2c21df965e92ffb9e55d385b10809b733a31b
ff0067:60edf48e90a27e6110eedd59715cfc9a148a30f1adf69e30f46ba1001c91c7ca
ff0068:44d6f904725d2a4994a73dd22c5eb53af7f6f717b82eca8c807d881960a89046
ff0069:bc846587541783bf7b47112dab5f01050a6a28e5cf9688d7bfb851b274be76c0
ff006a:cdbb42d596b27c822eb50fdf4e82dee36fd42459ee59c385d6cdc7ddef45cef1
ff006b:5ec863e586d0d39702a8a7a670e00ef1983496a4ce92f76d43246318e5b70a3e
ff006c:41a235ab60f0643e752a2db4e914d68c0542167de9ca28df25fd79a693c29072
ff006d:cc25e4426388361891f8d10011449cee7f95dd8bb6f782491fd4ab847c5d5668
ff006e:9b2e4d5f73be392e64a09c0b465713e6468d12c528f1ae300db2f96d6fb62070
ff006f:d5c14156baebc15ed815d995cdce2af299bb48b6ecb7da15c69f8cf8137dd360
ff0070:a3a43608494e512b75eb95a71d72d823fd1da012f77a24f752b7bc0f0959c317
ff0071:22914bc17c374f5fd197a45fa5efd4c8fecb283b300c97e61bf9950ac39ab603
ff0072:e60442ab1b4da076fcdf9d2567feb812d5da62c734cea15cf626f941c86ca824
ff0073:7c0912e5de8478bb86e8ea46ba5ae65dc3870bcefcbc2f46795eeecf648cfbe7
ff0074:09ed6e991fc3273d8fea317d339c02041861973549cfa6e1558f411f11211aa3
ff0075:05a6db389391df92e0be93fdfa4db1e3cf53903918b8d9d85a9c396cb55df030
ff0076:3a2fbe92891e57fe05d57087f48e730f17e5a5f53ef403d618e5b74d7a7e6ecb
ff0077:93a07898d89b2cca166ba6f1f8a14138ce43828e491b831926bc8247d391cc72
ff0078:973a41276ffd01e027a2aad49e34c37846d3e976ff6a620b6712e33832041aa6
ff0079:28689b30e4c306aab53b027b29e36ad6dd1dcf4b953994482ca84bdc1ecac996
ff007a:9f43d52e808c20aff69e02faac205aac684e6975213d6620fac64bde5fcab4bc
ff007b:cd24cd28de5a256f3ae5310afa8daeb744d770b062b4b9135070d952330531cf
ff007c:436ecef149b5377a7750fda2dc38a47b691c2878c8fa3dcb5ab40c80387bde1e
ff007d:d88a9b480da3edc3ec8354be3ac501c8f2def573f1c2632a2c6b2551b3065df5
ff007e:6e75cbc2ecc3704a8ed8aa9b47376b5287bffbd84d31a87328e08ae3c89c367d
ff007f:feb178196279f14374aa2a0f8bc345eccd4aa53d4e330571b104b848e33c43a9
ff0080:b335b2ac7291e13c5ae87a5378d7d422ea68262dc0cef762e8087bd86a8c2981
ff0081:de2d9e1f2a384f1493a29a6e77dcc2dfc56d63ec69fc4ab2ac332f22492ebe9c
ff0082:09bc1b137c031239ef788673e94eb17f5f3ecab07d3adbfb485e75abfaaf3b9a
ff0083:02ab57e4e67a0cb48dd2ff34830e8ac40f4476fb08ca6be3f5cd846f646840f0
ff0084:699d54b7482a5d329331ea0415cc2edcd60fda01d19e71d054196bce0677735c
ff0085:c977923c771e1a66c925a2b6f501732e678dc9887afe6bfaac039d1d9a71f0ec
ff0086:c94fedda4e8608908580bc7f87b434e03bb262e42f64c63820a8f50fb17c1cec
ff0087:4b7334e1d8999822bafa8ff6888125389b18a4e5ab26ffa624c7f68fdc81f0cb
ff0088:aa89c466e9d06882c0daaf72be0f0fbcfe7c1ef2aaad190640c4ad44f5517f34
ff0089:9bf9496777d14425ed0086c1bb2c0707b62a61c194c5162e4f07637aff166b76
ff008a:d0cae6947bc77f0b495ca808d6cde685fcd20225e1e530b635b113ed40728ef3
ff008b:61c1067083ae044ef1d649ce590bbf09d9d739e025da8d195f71cfaad6ebae69
ff008c:c96f24c45113fd91ae2f9e40e106653bfa0ffbcfa07e209524c844e7c8da4148
ff008d:239ffa86d71033ba255914782057d87e8421aedd5910b786928b6a1248c3e341
ff008e:2d87ff20fe8ad2305dfb6f3992867ed2bf4fe3e1346212c4345991aac02266e9
ff008f:2ab4dff69d75bbf9541060b434ce5ad0c4dacb7af0dbf21d3616afcb473796de
ff0090:129fb5de501e24041cd14a81075fd1cde257408d4a353e636912e38bdda2d3fb
ff0091:fd02362244f31266caff005818d1004ec4eb08fb239aafaaafff47497d6005d6
ff0092:6c47d365c13bc8cc3d6def5d8f07ab8dbea3c8d4945d651aa9854a9c9a3cc71c
ff0093:9e852c59dfc6fd6abd4e17ea80b5f4e56fc04192d107258d54da8a92528670d6
ff0094:cf1ea15dc9c05abc72af0e62c48d93434ae0271b1aa4318be3544126d24b6184
ff0095:949424dc2ccaab5e9e80d66e0e3f7deeb3201c607d4315ef4c6f2d93a917279d
ff0096:c333b61638b0315fa801cce21cc4ea96ef7f65a3999450186a99d19bb20128f7
ff0097:59a3456e750e325fcb1359dc29e828189b4982c119c64facfd6728711b30532f
ff0098:0f672d92a0b06cee948f03b272502602c6e37d2a2ad694a31d5de313196e9282
ff0099:f9690880819f06cdcc0b2f224b207f2af6003fb57339b8679a160fa95208d62d
ff009a:6b9c08e86eb0f767cfad65cd98b62149e5494a67f5845e7bd1ed019f27b86bd6
ff009b:4bd16f4955f3f3c9c8ea48ef9995324da5121724f89915d5f2c91eb0baef2337
ff009c:dae3434f696fc9f0f652e1b2a6f69b5e9273d09f43bd3bdd4717d6141f8cd2c2
ff009d:574342adab4ed79ef7818e8299058e1c071ac0e431fe421cabb62df4d4e9e4c5
ff009e:74afceece0731587b45c3cda7bc210fc917502a323401e932e865bc3d797e7ab
ff009f:40f47955bea3ea726cadac5d3fe61297fe7bebae5b0509e1ef7b29c838f49d20
ff00a0:75894d4c94c22d7296ee19fb447623258c2591b17031288bb386a20aa1f0e0a6
ff00a1:a5f2fd0d66db4dd77a2914ed3c747cbd97e734cf4e2b6f217fb41aa4eafdead2
ff00a2:c56f0f286618c1e7b0e112c97b9ee96feb4d71e79496c151fa1fe8a8cebd06cd
ff00a3:372b8f4ce73bedfc88718c407bb6b3e6d8f9a79be957190d0e7101c7b0ef9a32
ff00a4:bb661d750c53166181807a6898fd464065ce59298986ad66d9d6fffcbbd4738a
ff00a5:ad47883a48c86a3469e32c972b39a3ee155804d32bf53ff002000bca11d295d9
ff00a6:a1339d33281a0b56e557d3d32b1ce7f9367eb094bd5fa72a7e5004c8ded7cafe
ff00a7:b676f2eddae8775cd36cb0f63cd1d4603961f49e6265ba013a2f0307b6d0b804
ff00a8:b884ed6527433687627d35157e904690d2dff6a5dcd3ce267bbaf159c06f5054
ff00a9:2d12b619a660cefb013271831d891213fc434e982a21568256cf4e2e86324bea
ff00aa:9bf58967545996194512db6177151afe99706aea3da36feee7ad9f8b3c0507cb
ff00ab:454040e4969070401cc35bdf7f2a4ebce5797bb7694ae731d93a8115fd59929c
ff00ac:e22e6b25908e1107a607af060e0b24e50c6d9562ff04f455be0f8df41a5032c0
ff00ad:87dcd4dc74640a322cd205552506d1be64f12596258096544986b4850bc72706
ff00ae:8b358466d66126312120645a5875a6a57e3c81d98476a967604244254eac00f0
ff00af:40c826fdb22ba32a2f9db4f94770f72b8b1da9c8ffda7b11e6f27af245c89b5e
ff00b0:543d9b7fc2a6471cd84fca52c2cf6159df83ebfcd88d8b08b5af3f88737f52e6
ff00b1:2b75cc4f36759cfc4c6637b1e0e54359457db57e74de4d2dc5d02cddff2960cf
ff00b2:0ebbdf146e63f70faa5927ee8e5346e9c96c5f0d9bdd3212b04ed6687179874d
ff00b3:49695a5f0f7ef6edf698193d99ed48baade20ea457403c11cead492c458665da
ff00b4:8ad47f6d70a44fa80af0f931125ffe3a76876ffad219a4d40a13c038dc85e69e
ff00b5:cd6eb937ee17a9fcff60a790f8bde0ca9abca07b3ef46074dd1978f0bca4d449
ff00b6:7ed19361ad734d703fbadf029f52ec3b6648d8dd56baba0884ed4f859b5b9375
ff00b7:25303cfd0bf1baa1ef248c29f073fffc2e7c81582ee23b45c7f1c3b32e341ad8
ff00b8:f8684d2812ba98a52fe94528c4cb152378a2d73a828810a8c7b8529875c64674
ff00b9:cfcb60c1f0180c68e3ea5d24b4a05e9d9900d87c3d83d503ce1690b3c1656458
ff00ba:b0a6ef0350e7c4c6056beea7af9d2d860b9ed102137b9729d3c23216d195546a
ff00bb:c63543729a370c26952b47e1d1d1aea84cb1b07f1b0f964c2feddc523fd7c795
ff00bc:d0e39aa7d2fa53581008a15d825c57d25bd49247834431f8a227a29c280a1c0c
ff00bd:eac241c0440a36830111383336bc20cac7409c20f6e88d4f84f4827be919e338
ff00be:111006378afbe8e99bb02ba87390ca429fca2773f74d7f7eb5744f5ddf68014b
ff00bf:391220705b75bcf3ed3cd4b3631213f569d2cf8226101e170799a5354ab12861
ff00c0:ca290389e0d8c62a4083f628a39f52fe3f38b73199cffaf7c0372378a440fb6a
ff00c1:1835b0e482ea65536fc010e4bc13c060f65668165fba97e2f542ce96ca6dfefc
ff00c2:3447b74b5e500a549983fa2ced73a5642e6aaec78829546158437df66d7435b8
ff00c3:13efb39a2f6654e8c67bd04f4c6d4c90cd6cab5091bcedc73787f6b77d3d3fe7
ff00c4:75c5b3f01fd1f51a2c447ab7c785d72e69fa9c472c08571e7eadf3b8eabae70c
ff00c5:d82f87f93d31d5fc818dd66bd50e7f319ae179fc1c5d00547b658e8eb3f4ce56
ff00c6:58d7a197f09a6ea552b8ea6b1a53185a030a3ad8d52220c00c44e3f450e4fb90
ff00c7:f2603670bedead1d977d6992fa6554e6ca595bc50f3b03f416dcf0f20dac36c2
ff00c8:5b87e222f20346fa3628816ed6ce71faaba0857fb8bcba73776ea1fa56cd0057
ff00c9:64853613c2436399603d0d560b52f04bb8f81a81746e42389883a4f59a4564d5
ff00ca:3fdf788a5a65e6a29d8c1550d8244906a3b8a7b7d3da9bdedd748e4183a763c9
ff00cb:c131499fd86b213db5defaafd53111c28a2ddaf4ba465c8265a72d6cf739b668
ff00cc:4fd73419046f90868826d581536931d22e54943ebcd059cb7621394d749343c5
ff00cd:8c88ba510529b64263ccb21a73d82ba5725a55c1446f2547bce301fcdc4314db
ff00ce:62fb9b6cd2633b92d91db264ce678a9b19c575414ab10ad46d157f07bba26eff
ff00cf:ef4478eb094c48fb9feaca09736270499ca52eb04e3f8ee4c1b2edc9960398fd
ff00d0:9f4e3c42fafeda3cf88c05cc4b4af0c0af306415c30d3d1eebedebf7d177a982
ff00d1:e86bc16cc6491e5f4b9976313842b3d02c99ea263aeb1dc223d898fa87c84845
ff00d2:ead62f42bb369dd43cf6131ac2d8d72e4f9fee85e69d45daaffe326aac2a46f1
ff00d3:d6ea1061c28b3db96ff5baa140ab5714e6b0b4f5d71abccd242a49b9b9f4dc27
ff00d4:80d9edb45b7f592cd30254e55bc316bbf44e47dfc0c004a383281c03f345ba39
ff00d5:9fe306e663e459644644f60a7153a221436fb9701a0ebd9124eef8159d15cb43
ff00d6:ea8e2051623e4e4710fd5bf27a4d2ce0be65b17a1e5439b8fab74e01cca81575
ff00d7:249be65f0c7ab0fe3b7648b30ce0eb3cf691402c72dacb40cf14629c603cba36
ff00d8:3284e035ccd71f7a1d063ae98e29b1e5912311ad9f6d911884caf9d771d37c4d
ff00d9:ebe0015ef641c480954ed2a68842fccd2a8a79213aeed836ddfa6282e8ea8f6a
ff00da:21ee6d4f5fee485ac7a035f1d65de2fc4dd0ed2897acdc2a3b679c04d4599ae8
ff00db:194cc2b5b06493c0ef0b0a9fa8376f958be242a274ada974acbc9102336878dc
ff00dc:9b22e7fa08d3f8c6d6e9f420d8f756c79135e66d1b2d70b07903721f03dbe5b6
ff00dd:2c73ee9a52ffad07166b8728d7681d8cbefd99a90663345b25aacf9b1ef1f333
ff00de:7753300564ac665d56fef5bdafd99c88a731c21ead8e3996cb373e79adfdbfdc
ff00df:3fba0aa49fbde1c814ca830878ed03c7d24323f63483e52dee8ff42c153c234f
ff00e0:c5c5fcaf6e4bd0ad95bd8bebd1aebf165d1dbf449a812f12c1ab6eab6cc7915e
ff00e1:f6e9ceb1f3c3689851f886055531da72ed0bc5e56d164925b3ae7fdce8717d70
ff00e2:e942ff83f633a08dbd65e43b5719a4340de13db7c61bd6a87cdcb0ba9875a968
ff00e3:13c6b7395bc64fc06cef2ce53f66d4b9800c52cd8816ee37532f3ab24b8165cc
ff00e4:722d50874da45496d0299627409777603a87341a5f943b889c32e7b9280a8f71
ff00e5:4b2b72ba0be27a63478c273a0c5b52f69b89e3699aad4f3a1a0eafe66b995265
ff00e6:2028b5221de277ef1e961f4e3182a3c500ee5aa67bf5b544d3a6d58a5ea6777d
ff00e7:f8132a3b1d19025c5e6eb3c1b76b534658c11a5be69044e9d4447b579463bb45
ff00e8:a7b7702bd26ef7f067a1d3975ec1720b46d6e01fd101ac93422eeb0d6de25f32
ff00e9:df4ecb16110edeaaba07a781ecb93fe354961b3131d2da5072d34abe0b74d5b8
ff00ea:6ee065af58b7043cb2372fc6639e3486304fcd094d9cb6838d76a88ce20c30dd
ff00eb:5367692ece62b758d04d9b7e6dfb0db307f859ebc6a6cb5f77ff24561d7cc004
ff00ec:125a5fd7c640d5e59f5ce5763cd8c932f5e597dddc4eaf1d59667cf4b556a237
ff00ed:2e4a61e5238e556e8cedbcc0b4f3de2178245664a0be195b3855b4c85dbdeeff
ff00ee:cd6c108a0e641f2ca122aaa6d03f826759cae7c6f800eabf76dc48b67cd083ce
ff00ef:7e32368e24a2cc48d3d29e883b260e40ceda22af97189c78fc5b928484e9a010
ff00f0:91d0050633f62572f6796148867644ee31140ad72266e0f9305a7c6fd4040f9f
ff00f1:06c27461c0417d513ce0f634fab5add30c88ef0e25c84fde0e42125b88ca0475
ff00f2:549ab524e886adece70bdd96a04b554942c374be7c29c0ee818b630bdf200ee1
ff00f3:90c671e08e6823b8646c2ec18023769ac0fc3438a33c101f6683b95de3180524
ff00f4:a9f8d0ec60f72d8ac879f6e3cc380e500098bc0080c07ac539fae682543ffc02
ff00f5:f301dcc5181b941090a9177e9ffab4795b7ae9a7d2360ea6fda3cce0cf0de49a
ff00f6:8cd953c506228bf1d74d6062e91e7e0873eaebbb19fbf200acadc23830006b83
ff00f7:d2d7d4bee8ff1b7deba427740081c07f7b186a2f29a12360d53f8c20d455538d
ff00f8:04f7a1c112607e593928fec786cc6021bd6ebd95001f1c693b8c4b384eb19f6a
ff00f9:bdfd84d902aad010c4e08131775afb7365694ee81c9b8ae2df76419f3edf1be1
ff00fa:769f6ff09a7462ac27a6e82de770013d3c02133afddbe581aefcca1b0a029180
ff00fb:0bd1479187ba01ea3e938a750c7bde3b6f285dc10ebb995303f66601ba5b2d20
ff00fc:4590ab0142c786711f56e87df81ebf9891a78043cd68d07029433f3518ec76cb
ff00fd:15fac425aa84404b362fa3489eb67d055d5da276f8685c4d698da1830d420f0f
ff00fe:9147c38e03b46c8ce5dddb02caa2932f1e1675c0a001529138336ed10d99983a
ff00ff:ff201ca12c87a6f0cba643e9abb3c954c9155add3139b2e2eaed114bf9f75d31
ff0100:bdaa384720604ff4653b00da3873a8c545996ffb8ab91d616f10495fc026e8fc
ff0101:39c79d2a4cffe09c61de69ec14991d8e95ce7134ecf71ef079900d0ad5478cad
ff0102:987a5c9584b46b59878e42460f83e4d61f4c2722366946d4d216f336a6f128f7
ff0103:3ca18e1edbe6860d70914e9aa0db8e61e193e7ef547cdab8b4df545f46dec6bb
ff0104:bdb7aa28f164e4bc15d6920733b223ed98e55220a3e56f3b1ecfd04e87d30b71
ff0105:5ca04e93a5a07d74c6fb4afe1b3d4dbc62c25ce74d8617c7ee66cb5438ba657f
ff0106:29a4ec8bca32dd91f1120de14f5bb439356d48ed80120df1a3a86617ea484bc8
ff0107:72956a1c5aa5d91ac69cd63107a25aa1843819ddc21c5108ec1d97f3229603ce
ff0108:e81443141e3c1232d06465e11bbd1f6ca7181a3e037f815bb8faaeade6bebed1
ff0109:cd730e53fe732d8f09d68c2cdbfd1efd98a855f5e149021c01cb2eee1d8186e7
ff010a:7e0e16c0056f41a9f4c61f571503c3bcf079e2bddb228bf2219ac31200496b5c
ff010b:ab2c93e01cc215807f04cdbfc362808d88940a7b2cee70238d356d8d94956df9
ff010c:f00322c97b57cea6d64a6a1d365c6c6b7f0eba3089876c1430e1063e8a82a676
ff010d:821cc55ce7ec5c74febb42f624eb6a36c478215a31ed67e3cf723a67e8c75eba
ff010e:6be7d04e20ffc28f198ca88fc0c3644784fd156903bf078130fb964c0258dba0
ff010f:e11e06861c4d308fd944bf17be5e9072a034c4f93034cb59c02d512d30f7fc45
ff0110:1286173e6f0102f7bdd32c2f830910953489bf22c16295d84dd90a3da137164a
ff0111:46d3b50fedcf8c36b5f672239cc3a2e9e02ed15f33cbdc0c262a8647849403f4
ff0112:3997c721893b3926d3938a311ca07a261b2ae22e01dc587f181dff15b98b4ea6
ff0113:799e20564d45484dfa0f28ed726037ff070d66c51de8e2343284decab0fc9991
ff0114:cc7253ebde9f7e92cba297b5baded1b22e5ceaca525e201b4dc410f4f3504b5e
ff0115:0531c86f785958939fdc539924d395d1efa409364e6827d3ab9876311ffb27b0
ff0116:da5462526a0c2e9852a86186b025390158759cdca6ae21f09f713ca6accdd1f1
ff0117:526e30ded6bf9d5ce216f50c832402b48ab70d55aeda918a1873a5883ebdb1b5
ff0118:dff583e3a1ed35e57d95104817ad823c055fb9071cd400435b5fc74e692081db
ff0119:a4fe7c7f15155f3f0aef7aaa83cf6e06deb97ca3f909df920ac1490882d488ed
ff011a:abdeec53149098f8a0b07efd972b345a89bede8ede6975e61be95ee026da7efa
ff011b:5a49b15ae60ff627da272a8743d67162baca1096168203213acf8227af4c4942
ff011c:77d6c2af5a7b86f63d9918c87533779f2af08d35cfa14da4938c803f53de18a1
ff011d:337c625377592f1dfcc6e65631c605eb8b96e00c146b437fc1f067268154e959
ff011e:45b2b08e1b58948a028be13a67c0e20d4b2466ae2b6ec6250ebb10fd6b7f8239
ff011f:5d28761cbf304eafcd127b34d614fe179ac7744f1552af1c31298425ad05a275
ff0120:1d0cd7ef3c19265508e20e58b3538964f4a11adec8a71d8ab8a8aff15683c6ae
ff0121:c49c350e5a8205e063e74c554a994335b8435c996527d4ef1a2b0c7b51584b2d
ff0122:f07bbbde076f9b40c57cc4befede97ca1f53b9ae147f035d284cbf53f3432fb8
ff0123:d721110388ca6f20bba9fd1a8dba4efb8c16392a3debad97c553eeaf0acacaac
ff0124:18ce6cfe7bf14e60b2e347b8dfe868cb31d02ebb3ada271569f50343b46db3a4
ff0125:bfff8fd04433487d6a8aa60c1a29767a9fc2bbb05e420f713a13b992891d3893
ff0126:1ba5b2aa8c65401a82960118f80bec4f62304d83cec4713a19c39c011ea46db4
ff0127:8f9adb6d895dab5adf5c3d3fab83927be0fb64ef82485c62280d584e8bd55d22
ff0128:8ecde6884f3d87b1125ba31ac3fcb13d7016de7f57cc904fe1cb97c6ae98196e
ff0129:e35d28419ed02025cfa69038cd623962458da5c695fbdea3c22b0bfb25897092
ff012a:a040929a02ce53b4acf4f2ffc6981ce4496f755e6d45fe0b2a692bcd52523f36
ff012b:5e3571f33f45a7df1537a68b5ffb9e036af9d2f5bc4c9717130dc43d7175aac7
ff012c:c34c5df53080078ffe45b21a7f600469917204f4f0293f1d7209393e5265c04f
ff012d:604d32d036895aed3bfefaeb727c009ec0f2b3cdfa42a1c71730e6a72c3be9d4
ff012e:7a77c6c61eeeb9aa65c4ea410d65d895b26a81123283009db104b48de80b2479
ff012f:c57a3acbe8c06ba1988a83485bf326f2448775379849de01ca43571af357e74b
ff0130:2a8da2f8d23e0cd3b5871ecfb0f42276ca73230667f474eede71c5ee32cc3ec6
ff0131:4be8b5a1c76c6aead0611918fccf9dbd398b67fb12294758bdf994d0f9682f60
ff0132:407c276bead2e4af0661ef6697341dec0a1f9434e4eafb2d3d32a90549d9de4a
ff0133:2cabeafe37d06ca22aba7391c0033d25982952c453647349763a3ab5ad6ccf69
ff0134:68ad50909b04363c605ef13581a939ff2c96372e3f12325b0a6861e1d59f6603
ff0135:d3d607a9ff24a19523b6da9d2c649446f8788cb96d9fd130972e120c13677730
ff0136:44b545aa8a25e65a73ca15dc27fc36d24c1cb9953a066539b11582dc487b4833
ff0137:ad016f958050e0e7e46fae7dcc50197ed8e3ff0a4b262e5ddcdb3edddc7d6578
ff0138:2605875afcc176b2d66dd66a995d7f8d5ebb86ce120d0e7e9e7c6ef294a27d4c
ff0139:eb7e05aa58e7bd328a282bf8867033f3c035342b516ee85c01673dffffbbfe58
ff013a:c2157309d9aee17bf34f4df5e88dbaeba57e0361eb814cbc239f4d54d329a38d
ff013b:46edc3689046d53a453fb3104ab80dcaec658b2660ea1629dd7e867990648716
ff013c:fdc8986cfac4f35f1acd517e0f61b879882ae076e2ba80b77bd3f0fe5cef8862
ff013d:0f8ff784fd985b360a3c5c874c9fdef0214e4aad840f52ba766d446e0c7455da
ff013e:919a18a28fa8b1ef60060f41d6caac20d3d4df7703f5fa5b63b17ca5e4e20bd7
ff013f:ea4e5d2b9c99560f13dd094b8121a623bfdd902038dfd6d772ce32ffabec094d
ff0140:8c506f3f6d6e1e7040012fa66c3eca859ad0b880870c73c8529a5cfaeb4c8c99
ff0141:8f4ea4364ff3188200e791090fb1eafe28eb49996d5ca3f515d4d04c0d02212b
ff0142:1e5a3149fc349c1dcd6e12cd5ba4aa6b400a4c14540423d57937723178ce54e6
ff0143:0424993c2815f98e6050873fadca510fa32424b3ed196d57ecc36e915e909102
ff0144:e1f2e95000f815e11c81490430b5d02c8d81d0d256c85df68b516d6c27761926
ff0145:7f59445c96aeda5c52b65a3b69831c2da9ac4f33fa7053c3abe263eba46d4b86
ff0146:b0f527d5b8f02650d290d0ff1d84532833d953c2b201d5534bcc9b7f271c01f0
ff0147:b4dae2869f79bc77c29ad1a2a88a3932af3a9593fe820fb263c0db89843e9559
ff0148:0dbbbff632fb5301a1a0d9529ccc2e91139a3701d8e3fd758e9ec6c9d3d8824d
ff0149:848eee281de2dfd6bbd6bbaf221aef148eabaa86c89baccb681938eb949d8048
ff014a:c931a0f85a052901234a54fd460d417f1a8b63c38c4811f79b98f3ae1c2fe9fb
ff014b:4f1139c42a84535657bb36c577c729d1b08b9becac2173c7dcef52941e2d458e
ff014c:24e4036e57693f2568d1a32e4b3d05c58e2c91f8199f975a091a1262a335128d
ff014d:c57777471c535fb0ea53ed36572f81c92eba5bb9f186ce2d61bdd5b43cabe847
ff014e:e9327a347cbe1cb94cdc9aa54cb31b6e43d68968d17d09ce326a091bfc2f0b11
ff014f:2de620f2d1200aa90b16c3ccf670fd7ed14379ab06fa8b031cfef8da051ea5a2
ff0150:572bf899fd774362dc19219625ecc157bb55434ea5166d5758dc4b4f890d6653
ff0151:4b2cba18efbce6c3c4a80aaabc952337000cd9346b768d062412a2ded846edc9
ff0152:337ac56f39fb8877b9f0524554b755d1835a807ffc9058dfc6de1b707f696123
ff0153:a95f23b52af10895886fb65323d29a9876ea7d396f805e4ca280d561c26e3dad
ff0154:a69c59966ebbcdfec7f4ff0288c86ff60356fa7860208b93b43a095b0600cc1e
ff0155:7816c7b0566b46783b1c15d8a28d8b0d20cfeb20b3d13f79446e15c4a51c91df
ff0156:44ebf0123e27ff1db0497bd2dae18155b2a414e6bcd9c6c8fb8f48398449b9e9
ff0157:f660b0c256481cb2bfc67661c1ea8feee395b7141bcac36c36e04d08cd9e1582
ff0158:acbfaebdcbce1ac84c98cf24140b6061a97318e926215409dc0cf4c7be506620
ff0159:1257aac2f4eeac6ca4942c2c83f0b67b41a3b47120c4d53429929513acad468c
ff015a:562cbbcbdebeeb3cb55946bdce248ca4a623d2ba6e77b63b754d3a571f67dfa2
ff015b:86cb1b7972ea7d6b34c218b30daaef25c294036ec18418f977fdd3e7784e7f37
ff015c:a29c104b100c3a7933473e62e4be6371d653a1604d04edaad02c95806065cee3
ff015d:283ca6939530c1b5503915051936378ae36871967b03e4c2e7c243f14967deb1
ff015e:b90e17ab4b8778b10f9f28cbaa7664de2ee3d66e1afc574d168edd24a10339ff
ff015f:b41ab845cab4db9cb1fe6505765f36a0868adc5df419b38979fb6a4fe4131f70
ff0160:6c69e201656440eb98cd0875764a1ed19015ed8c4427601aca9c68afa8973959
ff0161:199ee58009555dae2cda0626931c64391d6a88cccb1f9f0b2ee80b667f581c06
ff0162:db99a4f284ccf10b26de7b7a5d651725b857cbc871ebb33028d67b55510efcd9
ff0163:0afdc7bdd919b36f3f907b971ac993c257ea9037d04fcc9e1d88d4ca9e013c7e
ff0164:2e6084cb49747f607a11df14bb24e58bc7051d82ffd94804c569c4a0ddc270ae
ff0165:1a5ccd714abd7c7af52a0fa946bc9c8f8696bcbf227d81339430e5d3394ecc97
ff0166:e121c1694da737c17b86448aedc614eebd7946a7b4b91fb30025b636070239ea
ff0167:709be4eab0a3721236f28b2ab80f76fda251330b3282f515ea5e0b6c79ae6729
ff0168:31862233620e789330cc893e8b5e66705331b8b88b0ed30a44574d9e0a71c4f1
ff0169:aed5dd9a5339685dfb029f6d89a14335a96512c3cacc52b2994af8b6b37fa4d2
ff016a:524cf7331c4ee353eeb1ecd74e1f801a0f1f08dfa0322092f42205afc3a17675
ff016b:87942388d29a46c06fe1e56aab791594d0fb2e8eabf124048f130eea9bedd3fd
ff016c:d48d3d23eedb50a459e55197601c27774b9d7b18c94d5a059511a10250b93168
ff016d:1501f89c5c4dcf36cf588a17c9fd7cfceb9ee01e8729be355e25de80eb6284b4
ff016e:1a0d20445de5ba1862d19ef880858cbce50102b36e8f0a040c3c69e74522fe6e
ff016f:1e51942b84fd467bf77d1c89da241c04254dc8f3ef4c22451fe7a89978bdcd4f
ff0170:e0c2ebd1f6bad4feaae31a3107e69abee902db38b9dfbe33f0570bda3494c20a
ff0171:d43af9b35473755c9684fc06d7d8cb70ee5c28e773fb294eb41ee71722924d24
ff0172:9bea11c976fe014764c1be56a6f914b5a560317abd9988393382e5161aa0493c
ff0173:22a2c1f7bded704cc1e701b5f408c310880fe956b5de2a4a44f99c873a25a7c8
ff0174:3417bb06cc6007da1b961c920b8ab4ce3fad820e4aa30b9acbc4a74ebdcebc65
ff0175:85666a562ee0be5ce925c1d8890a6f76a87ec16d4d7d5f29ea7419cf20123b69
ff0176:350f568d9eb610c6a12373e6a31be9876fa784e289c890e7ba07f1c346820d93
ff0177:609930eb807ad420afda2a8aa61b67483039168cd766e09942a48bfe7f3bdc10
ff0178:f5fb67c8453eda34dbec8a766574f07a03548c084af2f5e6455ea769608d9ad5
ff0179:a3cc68595dfe7e86d8ad1772a8b5284add54ace3b8a798df47bccafb1fdb84df
ff017a:96bcec06264976f37460779acf28c5a7cfe8a3c0aae11a8ffcee05c0bddf08c6
ff017b:1cc358a6dfa0a76bb5470660d78f3b25f23ccd6395667e49ccfc8201da3d192d
ff017c:781acd209d3b873f148f5db31c680adadced40238d8c1bf1a2d553391fa5d0f3
ff017d:07f2ce55ca1aa6cb992719b1e423c1d02c1ea759a6e2eab4e150c88282e22550
ff017e:736b996d339684729c43cb397d1bb2b2f3f4a7816a5e3c5d589203f885c5d47c
ff017f:b5e4491cf1e0a06c19441fac295b678226429603fcc414c626e210b2efc95f00
ff0180:b8d5d65c23ff9d8c902ffe6bec1dd2f20693af20e98ae47751f1ecb298127b6e
ff0181:080e7e36b3c7fa96ecc67db7f4d41cece1d194401af196a4a47b79bdc4970574
ff0182:60af9e5f39d873b236be142bc706da571849aed7fae635fc5a1461a0cf7459c5
ff0183:a98c8ced93f9a43631abe4573864e06c5192900723e97d1eed2c0d7c68b2d079
ff0184:3912c585e727f2b077888f678f043fd8ddcee9e91e6628a6245b1b8ebbcc3912
ff0185:31daa25d142d08b90e640d4bc50b249f0fe39785c98d5e53e233259c0fae9398
ff0186:7239d2f770faff3b1cf8be2a05ec03edeaac053b554f90d36921155ba8051981
ff0187:66eae2709b54cdd1693177b1332ff036cdd0f723db3039ed311555a6cbf5ff3e
ff0188:bf32da954571659aaf715c13ee703e3643dfcbaeee2d82110ca68eb57cb67ce0
ff0189:9e4362a918a89009877c7b8b190e763ae012ad47c1cca5fccf166fc092bc2ade
ff018a:7ce1db7d16e9bfe80693214a3d7c6263aa24789e399017e69ede4802ecf6f711
ff018b:5498963dffa651604f467e108e65a183470fa9b557c129ddf8c9d812b4f0bf96
ff018c:ebbf4dc600c17da04381defdcfc119c3f34efb4a04d0860910b813c7792d7585
ff018d:935061be52c8ea88c034b39adfd522bb314cbf5304e5a7064735ddbda3242aaf
ff018e:71e653bfbf5e72515b4099bbd5ec8872812b47c6ec1fa9add327e1c92c9ea16d
ff018f:211f3083b9e77a01d0828565897a1ce945eeaae04942ccc369087d8080c9e4a6
ff0190:23bcd5d7a96a513a981ead27936e59a8028a807bd72860418f68b555a2911670
ff0191:02c4a300a09c1b893b11f9567659af95bbb9bbe7953893e36c5baf17b555cee3
ff0192:1345c2d39ae4b65cca71e88e9a2b29c71dc913f952e935a812b004dba7ae7957
ff0193:3bc51856040ad7ff6683aa85a0d34f9ea680cd23c37cb8a0423b0f89a24405b9
ff0194:8f7cc455e9a5507804120655d7139186253e43b00422e734263a0769d2f89f7d
ff0195:b863a8f0f8debc79b89d87de941f6f15ec357715fa0cf80e84b7a6cdbd8d3443
ff0196:e7373a39c23547270e3d20b247875fa443f4f2b665d5162601913990383766d3
ff0197:35c0b8a577d11c94ba665e242de45d6687522a531e391bb4d995d261f3829ab7
ff0198:c89c24b415a72c9409667e88fb5e6e92a38d5609c3c99e55d99b4b1d458990f9
ff0199:3b27df9dd93c112aa08b062a6ae3973f7e79a5191d7e9b95d7081780e0d6acea
ff019a:3003bf8853427c7b91023f7539853d987c58dc4e11bbe047d2a9305c01a6152c
ff019b:aa53452d589069ebd91423834fec288a78acc6a7b9d4d0f143d8c92e0b83d8e9
ff019c:01379eb7b85f68edc2465b42438097687ebe1eae49319639bfb342efc3cefa1d
ff019d:cae72f66d61afb9a697338e8f5358d8071bafa4ae4d2717c7e635fb5ea43d365
ff019e:0ac2b6086eb10db5576a3a1b8eb0e4344082c1b7d832504fcbf95a4804d51834
ff019f:464b0ec0a602f0193db5f33911885a3a61921ad16d2664e25befab10cfa6ed25
ff01a0:c9e40f4e83396f34a7c861817b4edab3dc1f8bac699fd50cb261fa9123d55ef4
ff01a1:e74fbda55bd564c473a36b441aa799c8a68e077440e8288b9fa1e50e4bbaca11
ff01a2:24a55c2ab051442d0617766541239a4ad032d7c55175aa34ffde2fbc4f5c5294
ff01a3:c0ab07d9071a4cc1d34409178f8bca058310a8b111ddcfa655658760226f50f9
ff01a4:c7f546f0c76c9a0da9992e9884e6248b7ca2bb6ade838bd7a03a8c41ee2a3064
ff01a5:3fde0d36e026b6e8ebe2c28883607c8651de10bd6c1fcad365e560f4ea2f3b03
ff01a6:cf88915cf996932c2b4cbe3039076d119bb728b4f31e49b63a5022fe65489a12
ff01a7:ea4ee2faa57ae4b539b63977fe5bb205b6afb32f7a73b2b363e4be02cd8a91e9
ff01a8:cbf8fb77660167e6baacd0df77cda397d0117ee2beea23b935317f8bb5b5e3b0
ff01a9:0e10bddee7512dbd79ebf0b4f48feed7c83c2bd3dd81765565f4ff110b7bfa42
ff01aa:6dacbb8945137b1dad4211b0436efbe06f12ace36904973b45ae25740823d369
ff01ab:33d57359831f87754e6e755d6b5b56e7e71297dddfea1d6397086604280f6ffc
ff01ac:ad806a9357b87d1eb1dd85a5a3c092d0204ba447ff4b3714e3f1034f4d3de8a0
ff01ad:690ef214bc114ef1d726bd7ef03e546cd6cb7be5bc23facd391263bffb57970a
ff01ae:7f07c12fff4653d6bb65f9ccfd1a0e9ee466884eb077277bb9bb45d76243cc22
ff01af:eea152ccf7517e16513206b71c17e204fa4007c26c36051ec67df4c947463cf8
ff01b0:df653085c8ed5f844cbb09161b8ae0bf2f36822f937bf7bb1a689c6fc8bd579a
ff01b1:583453ec0add8526801e62fb85078f0b24845f0b67612830dda97ec0e829f41d
ff01b2:d9352669e29349329af4745c55a6c159dc979ab745925170a1980668382acbc0
ff01b3:a4a7d05f29685679e3c00a322ce6b6cd57fdda5f2ef42c6c6e73581c8a471077
ff01b4:209e956af04df3996507c887d356230d6eb49fdbdd2d8a058ff50b8f80f690aa
ff01b5:710024b37bd9f0e1537c18a4c20f9a31c4b485d1248c643f20b4c00f3716ba85
ff01b6:ebc5570c29018c4d67b1aa127baf12f703b4611ebc17b7dab5573894179b93fa
ff01b7:cb2862ed0c9d07eb689384d812b896d205f0ae2aa55cf4ac0d67cf24ba069eee
ff01b8:981d016eb85502b6de8670598b2dd7a78525a391471f55542eea2a27d812e4bf
ff01b9:f038421f07f20d63a20d3691e5a178ab8459ebe570c1647b7690554ef23876ab
ff01ba:e1b295e1465c24e0951ec0b90fbf7da30b678e9e9ce4417dffe9f34042df4386
ff01bb:fc2245be59dc6461d4119c3a06edbee4d288556bd88c479e30ed5f3e81616469
ff01bc:01b9f3d08e31a9e8e1600d118c2abfd856875ea60827020469865ba242eebe1c
ff01bd:4c9e0538f985690de9d5ce1c38f16c24b4c39a1710c0881cdb06e2afdb757b4d
ff01be:8fd16a179944d5d1d420af09405eda7abf2a9c742883e8c2f89e0d90afaf754b
ff01bf:601293ca20b09a03295d196256c6953ff9eba811db8e3ce140413c1bffe9a869
ff01c0:db0da16032f1643a2496fde742e2bbe81daca58cd7612061420e154ce1bce2bd
ff01c1:fad540811afae0dc767cdf6572a088fa3ce8493dd82b3b869a67d10aab4e8124
ff01c2:b3943bd0c0ffb4b41cd9e1ade986abe3358312d6aa6c5dd245bb7b0d63a5f851
ff01c3:795015caaca74715d341120d3f0efd192a032f1c00391797f54ef9980804a175
ff01c4:986373dda59fd09384b0a47c8e3155ab7424ecda5dd82db2e2a43fbd7591434e
ff01c5:2a575471e31340bc21581cbd2cf13e158463203ece94bcf9d3cc196bf09a5472
ff01c6:c45d7bb08e6d67e62e4235110b564e5f78fd92ef058c840aea4e6455d7585c60
ff01c7:15d5b8774619ea7d54ce1ca6d0b0c403e037a917f131e8a04e1e6b7a71babce5
ff01c8:71cca5391f9e794b04802530b363e121da8a3043bb26662fea4dca7fc951a4bd
ff01c9:ca4389c89ddfc31bec26c74b44a8498c58b2d838516fa01b14f1393629e58a40
ff01ca:31ac346b31073dc0d134e29fc212cc4a15ed3530eea1edcfc8dacb36492d5de4
ff01cb:546caff9060eef30f4f3e02255fbf5131e657c1710c9a650020133a818bec1c8
ff01cc:419b0c9ad6b872a8b1bb87341af63ee92e69b27b996662e733032f1288108dfb
ff01cd:5600afb6bae2a83b66b9cbbe9ceec8f53e26420a69939a48dcc6d56b99790a63
ff01ce:1e96abb2d6502b5dce518ec00b5a1e543349efd2e3f68be9abc1128b256fedd7
ff01cf:74468180ce564bad7e812210af743e85ca96cba44cf5851fa00082341b2535f5
ff01d0:99442c8f83a3c5090ca50c1c0b1de4b32ed418ff0aa7c3240e91230159f3e7bf
ff01d1:96a5a2cd39800cfb6a2a830ee52dcf47fbb00ff1b03204db36915cea31f13342
ff01d2:55324a9832512fc6c99f15bf0e9ed3d6beb4398ccee194b7ff849d96d9130d44
ff01d3:5db60c2d6b6becf314477589a3a4fb4ccf84649d69b0b21b3d6b2aba78bd35fb
ff01d4:86c6707bbe27cde1215e25d3f8146a522281e18c45df2cb8c6fb7a03c1733510
ff01d5:3253412fdad4523108c098bb0ee0efedd7fafdd00fb30e47c6bba9fe3e1cdb88
ff01d6:64717250af8b028dd8e5c0bae4c9142c8b103532612bc487085fd3c319f9c067
ff01d7:527a60b02abf3a4a5519c4f62fbbd560e3034074eeec8b8799aa9368693fe36d
ff01d8:97f6b9eea4c24e07545a6a0242c8bb1d871e19fe03cfc30b99567971ae65f0a3
ff01d9:2316d05a2e2d347fa141135b98ed09f56e81f1cf5679793d3b39dd6d8e461a48
ff01da:891ee2e23282e5076c9ae9047de8ea900e066f81d6dcd9b843c59078b0f105bc
ff01db:aa61c2927dc89db225ca9a17d600373d058f696d86d10e2bd7b5e8f44a97eed1
ff01dc:af57fd805a0ef90e975765c0d5d55e3fd24cfc49b73aa1a49e1979018d54fc26
ff01dd:eb94f8e2c8d0c8338bb8ba40e1ead6224b842cbafc99f269eef0761e839c41a6
ff01de:3062918d9dd617925271bc7f8080b8a6a5d2185bbd880f7862fd4c043b194191
ff01df:0330286df3612c0e968dcd518a7a316d5e0790d1ca324b906b0ef017c0be3ea7
ff01e0:b82210cde9ddea0e14be29af647e4b32f96ed2a9ef1aa5baa9cc64b38b6c01ca
ff01e1:8e8c6ebf77dc73db3e38e93f4803e62b6b5933beb51ee4152f68d7aa14426b31
ff01e2:92a446d2789431227ff4b334189aa5a7b9302008ac3747e968c6ae68ad7aeb66
ff01e3:de2ea05839b82dca5283a604c7d8dff947f54695bbb4dafb964840b1e611da7e
ff01e4:076abc2269327eef500a0c57527262bac831f9d2df4ef2d439e74ce17036aa3a
ff01e5:97384d1e5aa637ac601b198937159fe8b39a2fd29fe41a86a0930b6560766a71
ff01e6:b0cd6ae7b9e20ec5f830fee01f666d5d90e6e229d06bc46a30accedfec889648
ff01e7:2e7bf16cc22485a7bbe2aa8696750761b0ae39be3b2fe9d0cc6d4ef73491425c
ff01e8:69ecdbc3147f581dfdcb522d9defb260b26784ad4955c74e6a52522ccc4c4408
ff01e9:c18d53bf9864dd09bcbcacfd672e2566d4c81f6889e36df5dd425c04211d0763
ff01ea:65353833cf234c79562164f90849c0d104dbabf8ee41064d83e8cbe03ba1c5a5
ff01eb:863b2d43886b1b807b07d7dfda5986f1d78a54c437eef554c23e4547a3a1f3e7
ff01ec:a478ad193683dd4138e3d1533d71800c1b1147643c885d3cb3df283ffc05fb88
ff01ed:4ab8bc6061743e0980bfd121370a88c511c4f29eb4bc089765886b64c791f768
ff01ee:f12241ee34c03a608d34dbc0ea465e1bd1aa13091554f9d4d086253ff3ce83d4
ff01ef:c3683f7d91754219dada4e8dc30e4b18bd3928b53d3ab93d07384bc5871ce355
ff01f0:d7ba3f4ff8ad05633451470dda3378a3491b90005e5c687d2b68d53647cfdd66
ff01f1:24709797cd505cd70f27b2a6a013af7455155cf7ba3e9ab6acf03abb12b8045b
ff01f2:7b1d60647e7dab721bce21bd2ec8d2af281207b01474b1a47bf5cf772a311d9d
ff01f3:6616da2dc8c81cd1d5acb8664d8715e07925915b1130d0d2284604620fabfa98
ff01f4:d12df63569f0f814514c2e29c93a9a133a4cbaa92d3046f8c6bc2d9d6f66f087
ff01f5:a2fe481dbd77689629828da50957b55b0d2cc4960601b3cb04e60c1dc3bc246c
ff01f6:191e0b48b78b7efa4822a465ad69b34405b878d10bd853d8e57cb8b9d9e50b8b
ff01f7:92e3770b1eb44f84c2f2cb0097c2fd7126bd212b41c2610e78ddfd8946761738
ff01f8:33cfb062cd2951e4dd1a256bed156bea53f290d039deefb85be95e1901216a36
ff01f9:afe1595e7097ccdfb432cea639bdee86cf2576c27df36f9c691cf03e1324c1d4
ff01fa:663a4e658fbbf74fc19b0155f2facb12cc9b697058f447ef791178fe9b8d073d
ff01fb:3989a31702e9e6a9485f3c92a77d21b1852c7f6722f23d44b8cbe72a926ec854
ff01fc:48a2f7d7e80d42e722a752d892381c06eec4414155c9d6452aa506eea4ed43f6
ff01fd:4d8ed4a3b5f3cf74fec875e8204212a72197d71dda3a07ae5fa5befeb61ec9c6
ff01fe:97abd7593e9ae8df22ff46c417c763dd69ac551e2a78b164b66b97e63b1f86a8
ff01ff:03b5ffe7db4d85717cb2ed07119dd63a8d592c2fd04f2988d1c074f0fffaaa2e
ff0200:c25f1e96000bc36e2aa5cd54bf24f48b76890a162e1ad8e104992650510626c2
ff0201:7a142b1a5e16215183a13e840a862a437e293d9366921db07edb54f138ac0d78
ff0202:bc0878cbbc4e0daf7a9da464ab16262a235bfdaed33b9f9569ba18ff34997580
ff0203:a416a2ba490c454e23b85bf087db7b137f4f47d9747e60f8692ff4c8df0e062b
ff0204:c06e307f7cfc1d32fa72a4c033c87b90019af216f0775d64978a2eca6c8a230e
ff0205:4bcc5e234fe81ede4eaf883aa19c31335b0b26e85e066b9945e4cb6153eb20c2
ff0206:4422e963ee53cd58cc9f85cd40bf5ffec0095fdf1a154535661c1c06bcadc69b
ff0207:2a41ba819eb6125af5cb4b8b0e9e954ece798c2a7ee43dcdaf7d395987c4d552
ff0208:319896e3954d510da3a4b75387e8c870b3bc2c3228d8550916ebe9abdcb7f921
ff0209:009871c3a4c607311e5ae92f01095f9bf76100b8794ab0a9a5210e6794c8607c
ff020a:036a18f5f0eb9dd5ee02b7854df5c33845601d8939cfb7b607f69d142c01d909
ff020b:a8ad1c25cc580b2131fcc6fc6d6513746f38ea99bd162c81b5c5393495175b18
ff020c:f7fbdeb82be99d41cdca419fc91859d3e5286c076204e0e903d678bb213ed89b
ff020d:a838405ebb03f5dfd8d4a9572ae6e0e3f356ec4ec134375a59db7b195dc3ec44
ff020e:ae82201f565e0439b7f4ad689327594eb974a4f781b1a6cbfed59bd382317f13
ff020f:fc16d53203bd9187d69cc99d2da551076b4dcb298140d6751f7a012966c99fdd
ff0210:bd193c475e4e67938bef34122b98b558a2882e7ed94369a6cb011320ef15623c
ff0211:877f24ce70f4a3047e4ea70bec1bc31be9b6533adff3a393ff9bfb3c81029446
ff0212:d8e269a6eb08cbc337ad6578c72135787484c99d2fb08cced029e806be1040fc
ff0213:8cc34e11c167045824ade61c4907a6440edb2c4398e99c112a859d661f8e2bc7
ff0214:a0d1523a0bf663550eb9081e9bddeda12814f9570b7697d95df2ea53d4ff75e3
ff0215:c790b47128447ec0b60f22bfcb795d71c326dd910ee12cbb4cc5a86191eb91bc
ff0216:6e62cbe3e42a41c50405b3e2f1a44257683267856184af9c02112070ac836936
ff0217:9a5eecee9c7d898bd81dc3bf066daf6aefb8db1c59676206d2bfdd682312c6f6
ff0218:bf3558f877e89d27daa60da9671676570dfbeb215d84ac5a37122d6776b78f6e
ff0219:185c0ae470423b9d4678a7c1055b5b48d90705505b794e215c063851336981f4
ff021a:f74c3b2c7e455d654d9ee5aaa712789ccb267b961c1a1ce48a69c860cd193678
ff021b:93569b26aa535e3e07c891c6bd2fa9dc0939c24db4b3726ad8531edb17c497ca
ff021c:cf7cfa4f9dbccbca6d20efdebead4e173b34e76bda1eb1e619f44e06e95fc208
ff021d:8560f91c3624daba9570b5fea0dbe36ff11a8323be9486854fb3f34a5571198d
ff021e:15eb0a75c673abfbdcd2fafc02823c91fe6cbc36e00788442c8754d72bec3717
ff021f:b1ac8cfb181b9c9354e1775fcbdfcfe7898c5cc9a17d76315b57c112eee55234
ff0220:1ddfddf883e3945b2cb24fa5b83788379c5ab058422ab979df66c77473988687
ff0221:68d0b2e8c85bf009b4db39ac8b5e2fa8e1fd9fd1e5028704ea9288c7e472aaeb
ff0222:79f1f5ab697debf195f5b7da65f95399682edaeb80115b9d42a6ae5e2fa98802
ff0223:7a81e8d6bfd0230771f6719b177070c7a15b6971cda2cbb311cc387055bcb2ba
ff0224:657cfe2fa73faa38462571f332a2363a46fce7020951710702cdfbb6eeda3305
ff0225:7a4fcba079f5bddcf0a76c3b03a377e155a53009474a1b3eb8f34961a53bda9c
ff0226:6cdf9dcbf3510a3bb402761d62d0c5e4e7afc51d9cff01f02bd53256dc567adf
ff0227:e81b01f9f5692cf3823c6fd35886542bfaeefc5ea94f4e246e42c4a9fc5fe8ab
ff0228:6869242cd8ad2ac77bc028947bc7d0c4f6e9cbf0899d65709810d89f94b5d70d
ff0229:b5f62ec38131cd14b1fc95b877f4d210be4bfacc7e6a6aa1422d89e34b7ac4c1
ff022a:18958d03afb409687a1bc263860d0d735a25a004ab60e0f0e45d6333587437ae
ff022b:eeda15ba000b006ead49a21bbe769f3ba6ce75c9249f0114d8dd882dfc0f2c1b
ff022c:ea9a43515e138ff7782fcacdb9c7e8e1a61cfd1d17096ed5ddd1f400d02b03f5
ff022d:d108c34a58c0e4a616449f8c48318023a229c86cd3ddd5d5fe6041a401c16a14
ff022e:d7737e5f2d3ffca429902e9f388cfd6c5959cd35a0fc103cee2f7e93d1c66a52
ff022f:d3533b732a518a6da68ef266085e11dfd114c0eb0092cd43530a44d54b913ed1
ff0230:070531383ccd100d3e9cd964db07aa5e845a0686f2eae3bc8a627b182057b1f1
ff0231:09033fe23996fe4a59c4c0f523d2560e31dfe4c17d8ea1403d429a971f4bd65a
ff0232:1e1741a12eb8da2bd76ea96c04f520359839710f620e80952f48dd0240a12cd8
ff0233:65eec0cc6c970cc1cd73659115dc8d904e6f12e6dc8fd4dda39d54cb30224780
ff0234:75f5c8db96b8e2148a6a958a478311f05c758fb7d96d5b8bc04e5b9d359c3b09
ff0235:280bbc34a98cc79606a89690e52ab72fdc5fff275dc366c4827b1656313e9790
ff0236:65e780dffcb53870ea4ed9e184bcf9bfca464848b4d27e5eedf63918e69b3b87
ff0237:7e9dde11f7566b0fac6228a00905a84e6360e9501a701b3e7fc832ea3b9fda78
ff0238:416b1f9e84e74c1d19b23d8d7191c6ad81246e641601f599132729f507beb3cc
ff0239:1752c219d0337019bc8c19347c9f2bbe37081fa6cc1b1b09a03758e60c307e09
ff023a:b66d28cd70e6d1b321688e1c47e63c43c76ac50312909d4e30d78f08b2ed605a
ff023b:96dc615d1f3dd9002ee5e628b2801eed07b91f0e45acadedee76bc613da06cbd
ff023c:e7f1526ea9d5147b7a5e1ae6abe31737a4666d1e8f03e633703bd3c3d9b1e376
ff023d:78ee237abb2354aa67ca8fb5e2bfa9b917a0bf53e2f3b3cab3dacec1e2c361e1
ff023e:5f18390f21490292a095fff380f2e8927dd3159223a76113ede357aa2b311c1f
ff023f:e05ed4a9e4c773308a93e849861225ae349a92bbd4bacdd4900ad4e73b131100
ff0240:aeffe4335ee56422e927f45e95ae142b9eb35979a7400569ae9bdea6caabc1dc
ff0241:25bfdb1c5fe2cce051ec6dfbf2bb24e78c92f969b1bb37867daedf93d1a7ae7e
ff0242:ac0ab963bb5f3da05fbc8687f98c2b6ea0bb499e6118c1a9136b1bc7c3c71a6b
ff0243:4d8eb49380ec72ac9fdf21fe1c6db2e9490c76beadd1f7b528c3ccd272c8fe28
ff0244:1a8d790af9b2b34d7dd6af61b5aa4cf1380b86095cbac2bcab35bd566d0180c3
ff0245:3883e6de4917a46b594ecc2d2ac6a95d43e7eaa8e089a91f9bc104ff16df8de6
ff0246:c3804de51e8c17052220ae1cad3d383e54d5b7dc28843c42f0dbd9913c1e8658
ff0247:2daac6fdfac16c548c53ff1198254d7e937761d22a1e7cc5c1a9462e971461f5
ff0248:4affe4fef39464d1788c660af591d5e601b261c4811df0a3dd9d61cafe8e5ed8
ff0249:ba6a0c1170e1c7323860749b5e7b0ed365975d8fc90740b15d70f843a2394942
ff024a:a206644f57afd10b94169498858981c16d633858ce0c88b57cf14fa2a92aacfd
ff024b:f1caca6ab2350a7668c13e41960908681dafcc7e368dcb8d47fecf9631390481
ff024c:33e8a4ed48930760ce1ad7a2d44f079b22f660052753976109e6fc74752552bd
ff024d:b26eb310f8faf0ef5b0d0b71aa65ec050fa3ade29134fb438ab6440288fa6e67
ff024e:6970e396621417dcee315aac28bb5ea3161f175020f7f4e9ba17dade58dbb08d
ff024f:f6bf88b2a8dcd4feb4015984ec2f1427c8017d140cf41f22ee689e0d6718012f
ff0250:ea6963696750564a228b3eb88e0fd4304c5da27a7af92d1d4199357a50078315
ff0251:89efeb25096ba4ccd40af4fb8756f0a4843995974822020914c4e859d932b7f3
ff0252:0e984339724a267c2a3dc4fcc8d020b3b4ba329a0ad7e390cfbf76e88823e11b
ff0253:38a7525022c9658caafc6060764fd51c6a5c5bef232d3e6c7e48af07a098df1e
ff0254:f642418e4d0c63dec785c960efa68ba745f38851744ef81f225cb89305314d50
ff0255:db476339ccbfcc9e4bd1d6cb606ca27f00679e1ef8a581e7236309b9d63ffe37
ff0256:c06ed415e7ded06e5a4a083a8025f65e45d4e46b6351e99adb47de48b02f8bed
ff0257:ef5663142f5b2d6b8274529b157df2f965a71873a5ae5aa5e0720244f2398b6f
ff0258:3240b81c6df552aea16d70229dbfeff24d50eaa9a2272391888f65be95b450e3
ff0259:767bc29db99af4c2a62649000d172fc6cc2d09d408c4cab6a8d99a1dd5dcf7db
ff025a:7ec8e7aa42195e9a36b858e29669eaa37d57b13afa2331bdaea6a1ebf7e46e7e
ff025b:ccf497ae00da5a1e5a822756b8e8f038e00d52dc43ed2f5d33627909732be0bd
ff025c:2106cc7907c64b8a5da2fc338ee94dfff10ef711dedbb4fc694ee092ec532b1d
ff025d:ecc295b6ddcd084ba7179fb53bdd1d422cb6c0a8d94f154d4a5b17780b7279ed
ff025e:2a015531a5f3a4ce589bd853c71dd069587322f574d85c9c9b9f9df8f86c075e
ff025f:7e8f914119bb1090d6204908e5ae1f40be24c1491cd7d5cfb6a93618cbc00fd9
ff0260:db3517d1f6732a2d5ab97c533ec70779ee3270a62fb4ac4238372460e6f01e88
ff0261:40f6af0346a99aa1cd1d555a4e9cce62c7f9634603ee406615833dc8c8d00367
ff0262:86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b
ff0263:125609aa301da0a249b97a8239cb6a34216f44dcac9f3954b14292f2e8c8608f
ff0264:bc4d809b15189d78db3e1d8cf4f9726a795da1643ca5f1358e1ddb0edc0d7eb3
ff0265:e67d18639367c5b29bf7a5683b56b0f0c23155c8fe9452bcfe51681436023742
ff0266:eef9066424c23508e9c65f84671b14e16da1bec358e75fc6382eca070ae861be
ff0267:93b281bd81d83cf986659dffd0af57993b92e6e4614162539f750524ce11bbcb
ff0268:e372221266a330dd13eb1388dfaaf1fab11df254b63385cb637bfef8fb5fb675
ff0269:47b2efbc3670e7db4b41f22c51fc02ee84fb2dbf3082a49f2c2688122e9210a1
ff026a:4334eeb2cc114f82bee6f8a7e5aea03a42eb2e1f70cbd66102e414d72f0033b9
ff026b:cf6d0333d0be2c69a42d453960dee9e109d9e8843ea3061a1671d6eaf85eb7d8
ff026c:63a8369dc824a42bc7ae6ee5d26aafd32df4af677ca18b941b7a57e33b1e3559
ff026d:42da1c562f80e46da7a321244efc23d0faa9febbb7aa0377d96b42d9e88ab200
ff026e:4c9198b673550858799ad2744cc083c1ba0027e77d3b8fd6d56cf53620d099e2
ff026f:6b51d1dcf4eb7aee424185cb1b9580574b39cb963863de3ec1ad31ddb076ce9f
ff0270:0116f17f97cdef4ade2e63cf2c1b064fd99f404d2b914100bc241f0781853323
ff0271:4e9b731567177e1776a96d66d9120b3deb28b800937ea4662565b3ef5ec8000b
ff0272:aba6a65dce8955baf0685ab88809b7699c174496ef9ee991533251494f43ce10
ff0273:7066a0f42f530e0db5afee72a3b04de614e7d2305c67d12c756bb215e37cb975
ff0274:70b9ba595412cf8614b76747fd683cca2759f42642164834fbefdd88505c4f1c
ff0275:f91aaca0e4e533747a0880bfcf6f26720dc1d05494c3938da6802290d5a09b32
ff0276:f6f159286a1401de5397e21a0090534a85f5e7b9f98fd4a5a47b1dffd4bfded4
ff0277:0ef7b863faabc384a694ff632daaf9bd31ced23e9246559a59ecd7472754cce6
ff0278:69b0dd09b98f36a9cc7bd7ffe8a00dcd319a5fc947c9c8af72c92894d8e81092
ff0279:05b30b3fc44f8575334bd812ef9fa8a52a75743e19bc35a5be3912eca62c4669
ff027a:d034b18751bee10aaaf94c2f14350d3f654e5b934d0dda592b31e58187a48952
ff027b:a061d445399714c38fc101a6e9afbdb381f112fa5de7d5bc14904558d1ed3276
ff027c:c0a578f2109e6f42d3d939948deeab729b20f7b23b4237abd8494df554cf985c
ff027d:db4591f878f6672f5b70733a66ad7c9537b97e6f0af5ca49aab8ecb2ce02f86b
ff027e:fad2e98649f1c606150f55269ebc035aea22ffac131de64ba6900c75d8447b7e
ff027f:5a9a03f2d3fe589be63cda11820a9f25f074c92034f51c047d34226d252ec025
ff0280:3d4511d0a80aa949a6d99b253a173471797c4459187a6329e736c37cb5493e46
ff0281:43cac31ef8e8ba1b4b16b8206e4c0a26c5badb2fc3aa09e90170e41b66c2fd64
ff0282:c3aa89a4f9f70c18b0fea5cdfdb35e487da02c10ab6d3f60de79ad4c94ae284c
ff0283:91a321ad7fd3c9781214d76f5e28eb0d31ac86697edf700e9af94c7485f5b521
ff0284:84965384498039cc9458610318303f9ccfc452e236780fbddc4748567f05a0ee
ff0285:1235e13812b9752170ce9bd3a3b60e66ac8c0cb44f9ccb5c768589fd9f27b9f4
ff0286:ba6b9bfbbf9698af91eb4c693466414181a0002ad528ff154946d586aa5d9445
ff0287:f7c7e28fb5e79f314aaac6bbba932f15e1a72069f435d4c9e707f93ca1482ee3
ff0288:d9e445b22c6fcb37b296fcd1331486569651a8db98071753fefc73d2c97bf732
ff0289:7bcf1c8a12ee0b2854a1b41070652b0325e7d0c20b9c44d4ace9c643387f1431
ff028a:445eec78bc61215044a0379656aa2d5db5e42f76cb70b8d14c2077aa943d4ebb
ff028b:5ab4fcdb180b5b6af0d262a2375a2c77d25602015d96648756611e2e78c53ad3
ff028c:5a2fc03f0c83b090bbfa40604b0988446c7636183df9846e17101a447fb8efd6
ff028d:b10861737b3ec9b11fa6154d23970ffb2dabfc28ae6a6bf56c3f3204266239ad
ff028e:56da6efef1d504134c72eedc3ae44aa7fa11b848820dbfaa86ca8e35d60edb04
ff028f:18f4368fe93b3cae025230bce7ead340fd90fb27f9a10e36fee89fc454f22788
ff0290:79c4091b05b15c1683128b7a355e0aad62e1bbbc3e5f3735370c06cc4d1afb44
ff0291:9253bfb668f3e743a525e48b5f750a8a66035f806297c25f8134dc8ac9635bd8
ff0292:387d496b92202d4c443cd94ff42da17df2f1e68e244c2fbba7e294dbdd11357b
ff0293:918d2995da1be219e3a7e4ba2dafa11a025eebf4d4a35a3a8b2db99e792c687e
ff0294:9df0d3d5540deae996c1b26da31d0ed4e60efdf3a3da39b63fa8381d3ba893da
ff0295:7fa4ff68ec04a99d7528d5085f94907f4d1dd1c5381bacdc832ed5c960214676
ff0296:72a34ac2b424aed3f6b0b04755b88cc027dccc806fddb22b4cd7c47773973ec0
ff0297:57d8bdcd58955a5590a57c6aafa581ed9b96bed76fafee969b139187c5a872c7
ff0298:61e97375e9f6da982ff5c19e2f94e66c4e35b6837ce3b914d2245c7f5f65825f
ff0299:3457106752400212903a3545ca3b2ef384a456972bd951d8d840c1b0a379efa1
ff029a:1ffece09682f87024a2a44b2c987b1fccee3b2b5cf021efcf23869224a4ca154
ff029b:b0547fd468fbb6e337fe01b010834e53b4c5b12649ecee76faec38b8640f8878
ff029c:2744269be81d480c51b21c1c26b7769a90564e6da0ae44246dd779ccac70da34
ff029d:89d3bf92914827afec6216de9770ac437ee8c5f227b3b29820a9ef33551dbfc6
ff029e:f2b781704418cc6d4f200f74f542c845c91ac77c82f088912aa1a3d3b307f61f
ff029f:fdd7c3db9d64509e008360402fcb1be1c0cbe220d3d282af1f9b3d8e19b3e4a4
ff02a0:b676ffa3179e8812093a1b5eafee876ae7a6aaf231078dad1bfb21cd2893764a
ff02a1:ad14a68bec949e84f6063419d63465d137c2add3e3a85e00e9e3ee82e5b4018f
ff02a2:6555d661d37f2494a23c2d5f83479e78051b6de76a147b506d6bea2882b4d066
ff02a3:635af6889f49060fe0e7babc0f23314fb118f3b18243dd17f47d8647a69684b1
ff02a4:3f319b2afed4a0f75127be59925550d0428e68763a09e273eb6a9ff8d18dbb5b
ff02a5:87c71553445eb3c33c3e0710711b99e9c7773f04d91ac38a9f4c082ee24101ea
ff02a6:8f19ffe02fc795ed70765d1436addf772fe0f0773da436edbdb42a2e30e2e828
ff02a7:f114469fb80778133a1f70e4d8338edab97dd42ceb8ecc01cafb70d6b87df11e
ff02a8:c670c79bf277af7e7b34a6aa4fa304441833c6bd01a70a7e9b7a2d94c1c1f926
ff02a9:9917bfd853738985e46c920419410e966c316982769e71817e27d0384bbe3679
ff02aa:ac7f7862e685c7a7d9826a58ea32d183d4893fcc8f8fd6d900c9769a987e77f0
ff02ab:b14d5089079c1d8f7649db9a5d3cefb1aac06f66afc49225c5be2aa19fd41a35
ff02ac:ef6f29f636f62bdd4753122f41f3419ee7c2877587be4a9807adf58946458e7f
ff02ad:a7e83056e9b3d9ddb1816b95518f6a5e5a1dfdfa28f60533b1c850855eaa4263
ff02ae:1281ad8fabe883f209e9636448d1a80c373daa7686c813a270fad48f5f5e589a
ff02af:92c748ecd127ae6055b1808464f3bb113cc51ae0073591b3681ec527c617cc80
ff02b0:f6722be44acdae5b5a8b3b0b4af9f4bf5e5fbc3961cf526cbd9769d1c6e14859
ff02b1:f5bcf3aa7a2d161a1821204f525337c6cf949e735ad3d336e4764b25a76c2a5a
ff02b2:74508462a5c2a4f25bdcb55cb259310a056b7d623dd8e55351f3b42f1d32486b
ff02b3:bac4f03dc635bdae067f7bfe77ab06d88b5ba4668b0f46157e53d6ca9310077f
ff02b4:72376d590d9a665d396a51d2aea9334638fd4b13d6f5e993298322f344f2b79e
ff02b5:b691b46a9a510dbd66b989da9ad06904ac06473d8d0d79f2195d6b13ffb4a183
ff02b6:025764e6e19d90bc6cc70669445593d53fc0d9836f7b9428036208610b539943
ff02b7:2af988f26f6ef0dab9055697f0941fb4e5c42247ca982826895ef29985d30cd6
ff02b8:392583543b93b10e0506de75d69399fcbbc1469c8de396066c756088b92241da
ff02b9:da8546816d891c1241e9387de436d1b9f7ea70dba1eb3d25f58271ce816a7abc
ff02ba:f518f0bb716521f0a26fdb40c304ff9b82fbdbe7acbd46bf0ef23a180188eb5c
ff02bb:5c29dbea9b7cc8b02418f28c1c8736dfdf170665d098ef681d903be76987d249
ff02bc:c9b06cc083186220618e61a8772640f824df69d561ad56bdc15ad56d0ce08608
ff02bd:8711ee539e74213f5f412eb4a18a98c3b58da620b4d43e75b0542afc39fc6033
ff02be:4ccf17c0c8c1c10d5876ec5e3280fe8d134df36aedd8444289b990bc3741e74f
ff02bf:9218bab94e7d5d1f81d62d0fc23e31c8bbcbee3545d1d7e9d3fd29b30bc188c8
ff02c0:beb00b30839b9bc32c32e4447905950641f26421b15ed089198b518ae2ea1b99
ff02c1:6f7718a79acdc673c6113f21a22843084a80442f97d08ebb400929be51d820ae
ff02c2:d6d244742e8fc5645b15010f1cd59208f7a63e3bf100083e146f182941a61d98
ff02c3:08a0fd0ab6369ee96191c1c246b79971a3db5c5f2cfc6c4c5cd68cdfebbe0e73
ff02c4:6f10e437cf15e54b7b4167c9676db8f7fd78bc0b63b01cb68ebd00c37334d983
ff02c5:af9f3bce85779a95c56b4e4d90cdbbf8d4215b9dd5b36c79ea80b05da922b1b3
ff02c6:c87c2d7b322f1a19af6bf34095a08275e2c16e0874343dfdcbdc79d0f0ee74bb
ff02c7:d00619199ba1d93cf9971c0c57b01e240c220bde981a5fa1757d975d269e7ef1
ff02c8:2aa69ed0228f06a409254105dfbbf5924c2beeb3edbbb6c5f99087d810dcf504
ff02c9:a75dc97c261d126b705064989b0f7e1c19c5ea4a4fe08c6a61a41ad8bf6252af
ff02ca:8027f453df0d4d7d521b1f57f06d4773dce7ccba63ee96c627656bfc11a20790
ff02cb:ed1e061a00b8e0f4c8409c63cbadd21550a4ceb6bb0d678a8a88973de8acb86e
ff02cc:a41d1216216ee3316902080c5589313597a5474dd7f21e78fcd9e7705837d547
ff02cd:c2e14a608a41bee20238eb6bf407582578beae11131d62825f0801525a11c698
ff02ce:012e7fa627d3ab6ed00496a8bd3c7a35b7a195abe13e45d95363fa85acf245c4
ff02cf:945522340e54b7f2226be9e6272f18d2c3d6eca5a579764518dac7b0e0883fc9
ff02d0:efcf30efefd471867eba62e42add6f698243fe315887b9d2486eb84cd2bc3ea1
ff02d1:b84a33d93ef1b1738475c5a36f35e4e7649a7a27bab8f8c51a133926c218f745
ff02d2:3e7f788e6f6cdc0482ec554906e965b4d073213cbfd545f6848097d2b0499858
ff02d3:95d9a8d30f6b1c069c296b3e106bc3ce01eb84ad57860d0f46bf7f15d053b1c0
ff02d4:56e4f454d982dcdce611b7b707db12c533eac29a25f4a5307e1c065713b0dc8e
ff02d5:dd6915403ed7cb00f7704792c8084c5ee0c7de4b28f4f1ac09658dbc34ea9071
ff02d6:5abe5818f6d02f05106c6c355540e1be217c2354b535cf2507bf8515e1a6044a
ff02d7:12ea26f6eeefec76ab8592545403ab88515b00e275d9888713407a86fc5c7fd7
ff02d8:6081bee5b0df191ac4e265ac0f6f7899f078b8c89f06055ae166af91df70d6e0
ff02d9:1648ce4ab1bb65c485cb2236c768fabb865147d426915b92afbca81e9b2ee3bc
ff02da:7df800075f5203c017364e81195a9ac9ff00c507d64a70f737d8d3e8cb3f0845
ff02db:4f83842f1f04ab1e04d4d8e751666fca82e5191cafc24062bfd1fe77c02ca4b4
ff02dc:42dc827f46fb5e85dffae47d3c690f501ece25d575d597a50d8f878fa42afcea
ff02dd:6a6f2fa13b2d9dbbb409802002d3370672760a2178d9b8d5694d660474231fa4
ff02de:974b82076154ceff56ed4db562186f7394a02ff387aa205d6367a8b08ff7faa0
ff02df:bcbc18c463b61f3a033b10c74974ed8a2c328afcd67a338d9871506a3515419f
ff02e0:2a0e3f2a77a80dcbe5cd52d50d65076ebd37fad531db10d6a1385a557f7b725d
ff02e1:5e60965804461930ac27b6dbe3445679eae4131c22afb88af7acf6a1917b5aba
ff02e2:11d9330d1a2398508dd50d3094eb28b1b44900d9928f8c22b25ef7a781bdb403
ff02e3:dd23355c61d59970423004729795caef77afdb39767a795740d4e04cb6158a99
ff02e4:4d67237b2cfacfff3ddc83c2ff1c92a8e0a98a71bd04ed39f8aff42aaf99371d
ff02e5:ee09d49c7cf441840da5158d0e70d4c6caeb4fccfe6758ee4cc45c71a287df39
ff02e6:6c40d07f4705a5b4f04c6aecdc5a1bf5fd38d2b6cf2db7f212ca251075be125d
ff02e7:23ea405bb51d89ca5b67504c0f7193fa51b77c831774094d59937503ff716369
ff02e8:4b9235a7fea69307129e842f392bf28e98c6f6084660abc44855654fa5099805
ff02e9:99935e20424535ec016f337b2be68f1349de66cce4ca5ab367f8f3738215b833
ff02ea:60ef412eabe7c3fc6399eed1b633b777747515b29d721b963dd258bc498ab292
ff02eb:06b9722a699c57dff1869f430b479bb6eb49aae1184eac9c5325c1334a34ea4c
ff02ec:dda8da736187d76f4f0ed5a5f667b54d99a98ae06091d0e3a01714e9221695ad
ff02ed:e36f165ff7739cd900a2562767b3eafbe67a34c83c3a82f4c21d5f51c3ed191e
ff02ee:11d5ef460dab3582b742123127127d54040fb1c206e26f025cb58458f225111a
ff02ef:68b9c761219a5b1f0131784474665db61bbdb109e00f05ca9f74244ee5f5f52b
ff02f0:a6cf64dbb4c8d5fd19ce48896068db03b533a8d1336c6256a87d00cbb3def3ea
ff02f1:70b6a10c0ca76dece7adbe970b76a37d8a02857b134c7505b184ebd5fca4f3ea
ff02f2:c161f5aade40fbc9723f0892de963d4d10405561a6bdc69a72798f918bed19cd
ff02f3:0ee82ceb7eca241ccc29d4e588062c43e447ede6c696f135acc411966126ba83
ff02f4:dc9455ca47f5fd9bf3bbabbeacf88f3deb3b58bfa85af404dfd21617ce90a0dd
ff02f5:cdff27afa3daf9f706aa7ac530298337e520c8b10a22f6514e00e21fd2873b79
ff02f6:57de0583efd2b26e0361da99da9df4648def7ee8441c3b728afa9bcde0f9b26a
ff02f7:4563b936e35ab97576f5aef1935d9bc7e9977841f0573bd2e16bcac9534a6af9
ff02f8:ed3c991466cbc45b5fd1da281028f9587b8219523647e0ca1b47f2c527d2920f
ff02f9:9df77488c4b74ac32e3cec4c643d001d5c3babfa4001ffd193dca10c8be5cb3a
ff02fa:b700ba49af4d19e72fb15a2dac3c213ba44c319fa7da92772b3682e12b781093
ff02fb:cde23a52303c3ca67a4bbbcc9582ff5c9203aa98cb0f387139308ce2289506a2
ff02fc:b5fd6f800334f565036b0999f8310b5b0bd7268395d8b267005697af7301c5e8
ff02fd:ef9138993654df92d2fb5860e28de8818a9f49db56ecb689a67a7fc2d5881dd2
ff02fe:c022d5ceaa275f2a6268fa79ac35653b3a730defa41f9cd8817d6d159bd33097
ff02ff:b0505bf2947f0807abae2d42c19343eaf08d1dde3f8745b0589a57362792e470
ff0300:88f438dcf8ffd1fa8f429115ffe5f82ae1e06e0c70c375faad717b34a49e7265
ff0301:08fd418b118853484fd1b066f1922a80f571d8fff7268d598b086df18b580ad8
ff0302:daa0435407fa44c28ab939e6823813605779093873a96649ad6e03b05d28626c
ff0303:54a89ecb989a1dccf4013639f38974a0bc0742c2993dfb6bd0cbf1f462964501
ff0304:3a014bef9de8e25ae4a685a5ca351edd2b110eb8cde33e17b829509d78fc5e4a
ff0305:9b25a6a7bd51bc5f5c4f06e0d1218fd370dd31fafd5cd3b627c82f202f1b4657
ff0306:edac9c45909f4dec7bb65f0a4fbf6a8a0375e52aedd66e06888fed7e3edec537
ff0307:85db0beed0668d04d7074000f98e84b08d0fd5429ff4a262de7cbc1528a1a1da
ff0308:8394e3d07efcd1e97ea6cba214c3a055c17dd9a7ebf8dde0020fcddb76f28653
ff0309:948b7111af42f546d579cff5ce2bdec82134dd9914842bddb0c52872eb604e39
ff030a:a1663e37b8992d819c69fb89707065cabdfe3d53c278fc3ec2601001798602f8
ff030b:086bad959765654fd605a59310a9e9823f5d0b6e926c650293d40e4e5ce86042
ff030c:b2b0f2fb322629a38fa060fda7214ef608d347deae7af7045059d5b9dca1147d
ff030d:e7ec24cefc0a9a54065212419815eb4729b2da146b1bca0d42609a69986c0f90
ff030e:97552015f5ddfc3c8788c006944555408894450084f100867086bc1a2bb58dc8
ff030f:945bbc825ea554f489d1fd51a73ddf2ea624ac7019a05205225c22a78ccfa8b4
ff0310:55903859c8c0c3ebb8759ece4e2557225ff5758bbd38ebd48276601e1bd58097
ff0311:354fcfc6162a0ee2205dbef68931e78033ece9d125e0824e49baebf82dfdd167
ff0312:0fb6ce80909d19afee6a88c959e9e9aa6466715bce05c6449feb530a086daf14
ff0313:2fba8fe915415049aa942857cb53137ffd3d9e5a47b27b5782dab9b4da7d624d
ff0314:0fc2520288f704cbe4778dc01ec1f8842a98e6951051c43f422efe5d34f512c5
ff0315:613c8daec5cb84505f83ab27c4c96163804bd43d387250df27d0dfc1ac138b4b
ff0316:e3e8005f553bb62561fe54184e3a9ba1c3f391e14fe1e429e7f0646bd57ecf07
ff0317:4dc7f409edea652eb4ffed73147b2c9cd832db77712a1d6361bd9b7d16daf598
ff0318:fcd421dacddfcdc158ee667735504c370477c56f81760da678a34f370ccf3a05
ff0319:16a96eb9c37edbfbff2defbb332b9317d885ced0431de75bed6e2695a9e334b1
ff031a:554153b13d2cf9ddb753bfbe1a4e0ae08d0aa4187058fe60a2b862b2e4b87bcb
ff031b:1edb6bd91274882db795bfc514f8aabe10ad955cbccfd3fd5a5b5febb2ce5b68
ff031c:9ff23cb9387b9e0083bd5aa1954eeddf792890aa8e67cd4d38dd28af4a439ad8
ff031d:6782c6e9adbf9216e268306d46333fbc674bdedf86b67be777079e2c0e36888e
ff031e:18626a3b7211128d563469c654557d13c9366d7fcec8b94db4f0aa7e05944041
ff031f:2e63dc1becf427f9902b49de6330fd3e8eebf88b14e653b3ba2e37d4e4880965
ff0320:f62e35aad345fb253863cfc0e65823acd3e7f0846d19b8326d709c7919a22d7e
ff0321:275bf0046e0270178b13b67e4db150a10197cb71f9a061fad36b3d76639fe186
ff0322:18abd6e9ca907bb36754d0c046ebb50dd9b95d527824d9581a31b750fcfdbaef
ff0323:c63df9618fbaf48662ba12abe87b212cf777c27a446a0fa555d7a9d191148ed7
ff0324:29f8e104df38e612bf4f505365b5d0b0b20dd4e89c908306484eb8374c1e66d8
ff0325:87d42169b2693551ca205ccf17f06f6e6651f7218cd6d26607bf5ba4dd2f26f2
ff0326:703ea0a173e2042355f1dfeb1079292d41ea68c046c9d45cc60dc5410104f478
ff0327:08928092365931619759f2b8b44ed2abc030d8af6c3c3149fbcb07c78a96ce36
ff0328:244a1b730ca1d75a69a52f5e5f421bb547c797e24afbe9cfb99c993488cdc271
ff0329:830cb443e912901efba8ff8f8e1bbce97032aa91238e819d8bd6eafcd5852d50
ff032a:3b8bb7bee5a4eb21ea8d9279f3f456caf3b89c56d6dd4c69a3fbd7f9e4ed9cd3
ff032b:3bb74b1e67f28769368af11dc499b31f4e0459a786f3b0d849b6aeb59d092402
ff032c:6eacb9fea6cc6bf4595b49c222c26004d89371eb9384ae48ec17b95784948651
ff032d:d8e18a65af78454854caa28fb2f5e79b57ec141f010423bcc8a71abfc0496c2c
ff032e:596156bc2a4315eb768c826d7cca329158cae3c6f8f760536965bee7cadaf6ed
ff032f:10c3f40e9bbe17b48f0b3c7c229cab0a20871fcebeccccf6a2bb320f0600c55d
ff0330:ced406787f36646d897e468b7b8b5dcae1030c3a75af1c9b105514b95ec6ea70
ff0331:5048dbabf41bd9ef7d5009405f41b6771ac888de3eac90b3058f555964b7e45f
ff0332:45c28be4342f072cd6219698c3ef2ac6dba73f19e04dacf2044d2f6993e342b4
ff0333:57c0788e51d7bd14470cf9e4f37d33fbc104c77501ebd957166d14f44c516c30
ff0334:18fce092fa3dde4554223ae79b0c499a20f4114c363079d23d8eafdc96739369
ff0335:67bbd91446d3adef9b21c0576996dcd8e6668d6b0c133f076b91fa71cee6b428
ff0336:742640ac67f8d71b2c47775074ad8c60bae2c0123ab18354c24c171932d86183
ff0337:1f93666da57e1ee43b19e7367f7225151d44a96671843ad6262288db4aa80377
ff0338:5945dc534b0b1f37735d5aed4eb5d664172f285aee60a9e7b18245aa0e1198f6
ff0339:e7fbd2da86de31ae7fe051c643fc45d31e67454b2a5cd8e43c6d656723ae8cea
ff033a:2bdeefa735ff7005dfe82e66641772d825e7a3619bbcacb13cfe2010660e3d9d
ff033b:adfb5a0f259309122bcd1f030260079882517255f5b38d33f8dab973cb60e0b6
ff033c:143dfe65832e203e4d28ec30fb60ba73bee3aeee308a3f8d194bb61e7d1d9bc0
ff033d:6f587d1bee2f161c4fc2e662053df9cffefe51144ce927d3143e4a4c348b8567
ff033e:c1734233c45bcdd1f5ebe41278df1aec1c88ac22c4d15125b8774d43e81efae3
ff033f:5718e3e84a286b0fa2a0b2db14e955df79a7655a1eb5be3a86120058196cc13e
ff0340:8a71de6559336f426c26e53880d00d88a18da4c6a91f0dcb6194e206c5c96387
ff0341:30fbba2c32238e2a98547af97931e550428b9b3f1c8eeb6633dcfa86c5b27dd3
ff0342:f3aa6d712a15f63f8350804979db542419a61b2b1d22e756c417abfe8d74a3ca
ff0343:bd30c0d1e7acb83efc4f5f6c62f8f3a579bab27527afae666c696c3a867175f1
ff0344:34ff2a4409dc1383e9f8966e8adfe5719eba373fd0ad5e2f49f90ee07cf5d4c1
ff0345:7eb445ea38a46a6411f0a12a0e16cd3d073e91b125679977041ffbce83be3c1a
ff0346:bcc3a54d7083116316ce03b9a40ca36f336f4839ac581862d4311a84f701514d
ff0347:c5453f7c147016a9aa0f5f4bb1d217debe1c2d368c53cf74d35f55c5233c498a
ff0348:232f6367cf561e00c83e180a9fca8546b3771fb450ebcb4a0526f8349c8ca139
ff0349:f349954e8fb6d44011bcb789d97d9a2cb2032bd5f0b598d1fb8a099f5848d523
ff034a:c84e1378b974a991acdcdd733421e3061e6fa21a0491c8902bafde3855e0063e
ff034b:431f630a1b5de6f0ff1b73318d01aaa9fe4a125f3026c1cc30e25cf4a5cbba3f
ff034c:4ca080263ce4bc24f1811cef3ffaca5a5ef398f93ebd0c5bcf5b7bd0bae67d4a
ff034d:62ddcfa05a63acfb7c2070a435263f226bf2039fc11d1ccfc736792e4466983b
ff034e:c5ada3486bddb545b3aa7ec99c69c1aed94274d5feca7933e0132e212f026671
ff034f:27ce27206502030e3a10bc96d3a20c3d8895f871fb6abe1d80474ab456f31af5
ff0350:16ad5125a0955af0264218545e74827e2c39a032d5d0bf665b17c3bf99d23496
ff0351:28730009138b4e1d6d334a8f2805a60aa3be9969d573bbb2f0516312bb7f354e
ff0352:f471c567c140cf8bcdc0aa76952132871dd0c07daa11e0982435a771e305ede5
ff0353:9b53f69d8447b01b01e4565b853e288b6cb82291da82a5b41bbc15c2f3ad6548
ff0354:539c13d6f2731252f99dd2baf43d40559c46c585758c4fc4410c7ec482dbed69
ff0355:747cf4d70c0ca9e63df6bf60ef1cceb6f9539fa8a534fb69f05c61ddf972a419
ff0356:ba2959fa448e9802c859f90cb5dac738ef79dbfcccd4d407943651f0b0456a13
ff0357:b131905cc7221270613b529ac9e786aa230abfe154a0acbe452bc350bd1efe4b
ff0358:b6eb4f8ad197073fe5203f8fcebfd5c509cde9ca3aa65ec59d203831424192d4
ff0359:c0dd060ff8ce556f35683d564e0e66b2907178808693f83f3aa642326bf6d0c8
ff035a:70dc86f9f7750b74b1dec8cd352ec25837c36e640f7148e08464ef5901e5a589
ff035b:c87ce03affb5de6319c219971f2ed2d8f6f5389e2d53b22dd2c562a5c9827fc0
ff035c:0d51b6cdcf34a9f22144787f3fd920dc8800fb60490bfc8d289a1953e0fbda4d
ff035d:ada188f830c313f6046488ec341f1ed4af793c6dc28c58600445dfbeb4163746
ff035e:40d69920ea05456fa0117de608b8a8013790b542097e343ec1cbce2dfb9713b0
ff035f:03ce9bc71b91fdb7cb3c5235cae0701cb486bbd628d4aade5841fc5f0aa37a46
ff0360:f614ae2b101484f15f66f4dda56ee6eb422728f179d94399ede19ac1d85a8bd3
ff0361:dbdfa91acc4db8ad83fcc7978e35d62f6e32e55108273c8ec998e3133580d664
ff0362:02fed3ba2e6a7843a318a981bc847061fd282d9e8847ffa9f54d785b6b81d6f3
ff0363:7867aae905eb8d55635ffebbbf8cf05a63b9b390665de2367ac1073e92913728
ff0364:23ddf08b22373d86158eb9c99fdb5366b19804560531372dd20dce3fb766f56c
ff0365:da3be2b6a6d9715c1295a42be526e0001d10e5d7540f06e7631b34e644934848
ff0366:70357b9e56d3fb3c6c009c38c7181454c462908dfbce6d54d60dfe1e506e14fd
ff0367:6c66578dc96ad13eb7b688bdc09db472d5fbf03b3bd21309665052a886d7e9b4
ff0368:c451befba87014ecd57851d1e682403e3ca60963773ae7faa00ffd6ffac8b2a3
ff0369:70db9ded944dd35d474ea15ff2aa4e25f393a893ecda54359d305bc319649817
ff036a:0b405cfe9a6beb098ffb969121c5f6710f3f7fa9ea101a6418f7af201d3d3938
ff036b:f015ce3cc239bfef064be9f1d2c417e1a0264a0a94be1f0c8d121864eb6949cc
ff036c:855dca68f8194d6d5bc94a51cf364cdcffc83825a122d8a62e47a118484d374b
ff036d:f6787fa8cad7d2c279a0374bfb503807cc6adcc7c23709273dd5a4047d1aef78
ff036e:cc0b2512ee20280c36f30d57084acb6b8636d94b481742e424335c7767e758c6
ff036f:7fbf5db4917639930076aaff78fc91dda0efeea86cad38a18d98947d7cd36948
ff0370:1e4fc34d26e0793d559e322fe111f1e19a9d2e34bc25d3c427b032a48d2c5b6a
ff0371:9d1cda1b9ef395afce7de0fe74de6d9ff5e0d2a43789116c00c6ba5bf44b9823
ff0372:4fa3126d8d3a11d1c4855a4f807cbad6cf919d3a5a88b03bea2c6372d93c40c9
ff0373:cbb9c44d84b8043e1050ea31a69f514955d7bfd2e2c6b49301019ad61d9f5058
ff0374:e3402180f7fabe4592ecc9e4f2c8496b8da51171fdbe67c66574e8abbf7cc146
ff0375:ea76f9f21b92bed698108566f5f09211b204c5035c9d019433c6358dfa0a73ca
ff0376:1bfd8702d8f9bb340f353820330c0bba7e522c63164c91f295414dac797f0863
ff0377:c2dffb3c1bb06de4c10926e517ff366f93892d5e02dc6f79080275db57fd6fc8
ff0378:fb8fec759169b9106b1e511644c618c51304373f6c0643088d8beffd1b997599
ff0379:fece9ada7aa49d4fea9eff123542095a880c004fd6933f9364b02b2e3574ea38
ff037a:668901e5764d7d9099abc21348599d9ff36b916ca839b351e6875b18b16130be
ff037b:48855c93594527339d98449689fab7c315ff5465066c516c29dbdcf1853901d3
ff037c:198e332f10fa0f58af083ae964bc6441f06cd0fad319b1235fe3ed0f7c6eaf93
ff037d:3edbfffc34eba02e0dba9cd119dbcf98d7497257377af8bc6210d88100120a78
ff037e:04114a5423da5ca7a0c78adc8b63d8893e3343084e13367c1af8324726ecfa73
ff037f:5fa49b36c72d03e42daa4302500d646c948c87ac36ed30cc3dbddbbe24c64633
ff0380:0207056d172c80bdfb6dc45be9e5808846078d1e6eef1b6ed70259ab332a64c1
ff0381:4c985b2368d66c9530b411d4c7eed6ca6b7c293d496d1e6d84f9bac8a0c87e15
ff0382:fbe615ad3b01c6cd756f7dd39a71293753020acf7fe16e07b67d82e7222f326d
ff0383:75aa1cbe7cb4bcd66518242b1989e36830107ab181602e7c079ac43767eb0bea
ff0384:2e44102ab58cb85419451c8e19d9acf3662cafbc614b6a53960a30f7d0e2eb41
ff0385:dfccdbf077d142d7923f6316dd411e462c7a8bc04781f2b87065a5c5e258a7e0
ff0386:c2d4fdfbbd82f4a1cdac4713e3ab0999560918d7a170dde03f7ddbf9a288dcdc
ff0387:063627355c941a1c93fc515cbaef2f173d4a646ddeb139cb8c75c1022222994f
ff0388:761503e31f5d1a48e1ecca91312dfc81c46265ba7feecf276f8c04d19264b93b
ff0389:18467c4e64d586c844a44466de5ba7a6d5969c7a92859a511c5fdad75b03cdce
ff038a:b9c974de139f6308d74ccc423c3bc0bded5e7ab4ad738b304b50d429c42c3d66
ff038b:88ce49e3a4fa37eae28e8e35f8ff8cf7568ca845639cef3b8dfdf4e4693ac14a
ff038c:da7e5778f62f87655b8fd24a89e651e57329dc9c0765a71158ce56443ca44e95
ff038d:9b2dd4fbee941f6510f716c04969b36428892765461701ef47d41b3289475d50
ff038e:085a0714524df7ae9919a6f597884439e12a533e61552d29d6a18c35096fc548
ff038f:33ef151efb08d1c44fb85cc3f23ec6873014e9f881691bd4938b7f251580b694
ff0390:1df6054d6641404633641bb5fa3742fda7d075e2514840ab61e00ccbbb7d341d
ff0391:a63c1398b5f8dd2d432fbe4c2c19142bea6d5d0221fae794718ae7597acca96d
ff0392:0f1554c2fd591b0256a608e1c136a837e7a6e041561ee08a911b2afdcd3c6c1b
ff0393:45cb1d874cb03bd5c5b6e079c8fc29e51521ee5628486301964a41f94ba59f88
ff0394:6b328085625318aa50d173c98d8bda09d57e27413d114cf787a0f5d06c030cf6
ff0395:fe7696573855773e37a95e7ad4d9cc96c30157c15d31765ba9b15704e1ae78fd
ff0396:8bb2f6883fed289a521ba27c478482950874e143caccec6fc025990c0c46813e
ff0397:6baab0c433d779fd6a4b6d56d6304d5e6ea5de689fe35a43038a4028f345df60
ff0398:743e328f329e194da252711bf6bff00cf63b6a4c0aa66b2e1967716910678971
ff0399:a5764dfd0454ad3a06428b907db8aa436da6317209eafd61dd42e56ae77f9b13
ff039a:dafd2506a7e917c126e5904479439d7795087f04fa7bbe614796727b9a161d6f
ff039b:9d19082e2433be5501f469129570f573873b2dfe8386b1f8a9dfa98c2faadcdb
ff039c:a8aee0ca4fbe090878a901cb564125574ec64ba28e9e90296ed3e492b160b4d9
ff039d:885e8e1dcad07714f3ba2cac9adbf68711fb2e563683fc4e334cf924d97cc245
ff039e:0371a553e4acf402459107e8f793379cc569130f2ee03c412fed87b5c1724244
ff039f:ca377b18866b238f31a8049dfd13609e549b751390eefcdb9a9a1353127ffb35
ff03a0:e993ad654d458544bb0e4da7ec7c5fba60c464579b1b22c65923ddd14a6780ac
ff03a1:0da20b3c05386bd975b1dbd37f0eb7689e6a32364396e0653ffa9eee606794f5
ff03a2:1b4f794d770dc6e05dc7a4158450f8259572eb6d59de667a3c3fbe08da012481
ff03a3:eb14470371b092ed20801e21ea396539b4e428c1708ab8c9b7068342399d3c81
ff03a4:f4d695ada936362ddfaeda644c7ccef24eb74dc438d381a28afaaa11477ae67f
ff03a5:d101062438bfb0af05aba79df00f4dd49e78b8cefd5ed929565c233611310191
ff03a6:3addc98240e21a72d9c40eb5058905aa40edfa345adedde5844ccb0f462d84f7
ff03a7:f8e3bf1efe08ef700c4edbfdc4ff319d58ecb780dfb0dda7d51047b39b28718e
ff03a8:0ed9963e1bba0417e1fc17bd38e92061f965113b921cb357f131f12f08534557
ff03a9:27efe682c7479c38133a0943666fbc9103fcbb1a919634e439711cbea7e3cfc7
ff03aa:a9741c3fa44cf9777a49b6f50eed5d0eb87e9481f3a45096c3956a5ee1bb8844
ff03ab:9a069e478cd341449ff28b7c7752c54aecfabac58e4b5028561649ab482080db
ff03ac:969e3200520eb2c69a9667587e6dd4d0b23f28f510cc1317670a8ed3613ebead
ff03ad:be0d6c9477b982092549add3d5c0bd19e8f13c4f4e85e9471297e1c5e19ac768
ff03ae:bdbf57bd10163a771b28d09d4c90188d596072c699bd8274fe4628d1250e49bd
ff03af:1652c66db642d0a524bf89ffdf3eed5a8e94b14a6eb07e7a45ea80c54f9e8593
ff03b0:a5e33c28e3013a71f5f760ae3b16595090043d2ec5209ec52903c4fbad258dad
ff03b1:7e2c537397e7b8d9b24d87f304c96ea057a407ce11d0b66d99ba4b8a22bb1167
ff03b2:9c782f6b0558adcb1cc9ef845320d14592c9220fcf0030c0980d9d753b06624f
ff03b3:1e8f051f2226f992d17b7cf17f0dece0aa769902e9fe8d11f35b19b18a5a14f1
ff03b4:46727b90c5a5f73375082d9b1bc9f17b445f5020a95e37dfdf1ef20b287c5115
ff03b5:673e34d7e1e6b25c187f391cc49138b4722a907e33f5b7487b613bb6dfe78909
ff03b6:aec863898f284d6cd4c6a3f6c3e6523480a359c33daf66fad3381849b8bb018b
ff03b7:3abbe63daf756c5016b6b85f52015fd8e8acbe277c5087b127a60563a841ed8a
ff03b8:309a7823bb3d1ddf44a573ec0bf9fd5166625fde73776184c62212b4c0b4e94e
ff03b9:36195e76d65598888b05e3899f2112a9c5beb678155eb815c3371ccba7c37819
ff03ba:21acc1dbd6944f9ac18c782cb5c328d6c2821c6b63731fa3b8987f5625de8a0d
ff03bb:3f3b0d6a207c50a5829f1b1fe1c6bc3b66106085774614c12227b766728ed2ae
ff03bc:b5f4c5d185a8c87c78b6f67dfdcfd4e1bbb073e77a264455da961dd9be91d1ce
ff03bd:5dd661d3cb33b5005cbed045a223ddc4445aaa41d1acb5df700884cad9ba4195
ff03be:d24195c61f9cda8562cd75e95565197097bd74dfc07ce2d1df41488b699dc5e9
ff03bf:8ac552ad577e37ad2c6808d72aa331d6a96b4b3febff34ce9bc0578e08055ec3
ff03c0:35a1faa8c81125666d26f0a6e864ddeaa70431cc1570dc883cf147cd196e4ab6
ff03c1:bd3a6ba80ebbc83a75d62f779f5d6ccd9abb7ab6a8dfa471b496e81cd6610314
ff03c2:277f0fca263e12856dbaa4dd0adf04204f7f98cfd72ce9c93807e377e34c8876
ff03c3:37834fa5ea40fbf7b61196955962e1ca0558872435e4206653d3f620dd8e988e
ff03c4:dbac2fae4f8c949b1a30cf871eab58957f6420b797a5125506b8cedd48f5d784
ff03c5:cad03a584e58539b89192ec49cea7a6d8ed7242ad5dcdf83f96d087f09f232db
ff03c6:083799e8b2b9016e44702ebf9bf369ce253fe1fbeb650e5df10ef44d87bf3bae
ff03c7:860f8e4984fcaaaa78c87f0713f203181b57d7b556fed979ce14dca01ffa4a54
ff03c8:8cd728f9c3391ba4360a10c66ca484c807651d6207f10633669ed8881fe91bf5
ff03c9:b23a29c312a7a80b0fe6b4e71b909cae92ad649e88766e56c9ee8e1d7c013945
ff03ca:9a296a5182d1d451a2e37f439b74daafa267523329f90f9a0d2007c334e23c9a
ff03cb:f628264c79dbfbdfcfdec643171bdcbd4de7483f9c80ea59068887ae449a2e48
ff03cc:dab3fa0d6e821006fe709ae12176aba2f397706cc9c71f5c1c0d098044daebdc
ff03cd:701eb23f95564cd5569cd20e5f05c2888900bae9ba03abf5abe57bfe04b54a60
ff03ce:ba0312f7b72f6b64b4ccee34b5f628cf65a1f3b9f16b8dfe7ada90c54e475a1c
ff03cf:cb57b3ff2040cb269497625bc90fa9d7b4ed4938c6f60f42f69afdf508ac2993
ff03d0:97c4b44316055f26a52a1f664ce385800a964a8552c99d2bcafd618e6d8074a0
ff03d1:e3c24279dd6a337f881b1bc692e878f4a31afe95851f208f94800b0c24d88c38
ff03d2:7caeec680e6497fc5109073f83816e798f27f8968a2663c1c95711b548192e35
ff03d3:75ac8e41d9a7cc758d3998fe030f638cfd28855823da4e9b56954cfbde054eb6
ff03d4:f269ac00b410003f72dc628afb3d950279630c7c5d0c82148a0fd24df4da4301
ff03d5:b41a4864f0d4ec4ea632d01b3e7f232775e55e22b3bfd8642ee1292280d0e47a
ff03d6:d619f3257b98756d28811d3cee9adad8bcae1b4367bbb0c73f6b5e558fba4563
ff03d7:72d0f7cbf4529b80c34a7cbb438bd1d0e1fc26e80e59cbd4fd7314fcddf0e994
ff03d8:e9529b428fb67390bc6455d79ba2434e816c54fe4f359930cb709db256fddf94
ff03d9:fc01b58fc78b9c59211784c2e25bf1d012a1e23f337218847a62eb4145ee4ab6
ff03da:8937e90e1495c9a78efb18182d43fdc73fcd292ab6347a12b9077de878530e62
ff03db:38392f17ce7b682c198d29c6e71d2740964a2074c8d2558e6cff64c27823f129
ff03dc:53612513970b9f264ca4bcc3bfd84dbc5fe774e3c6295b3ebb99eb9d74069e2a
ff03dd:70d2b96e7c040b6270ff20bb6ba98421312ad37e462becb83be9502b83df5697
ff03de:62806a3d942ed4f6c091a131e6363b138dd63a5c3cdf4413d00cc8a0c333a9f8
ff03df:ba799f322591dd7d35dbc58f4820725f094f543aa13cb458c55c91dc86be22ff
ff03e0:b7e1242d9694fb5025b096964fa76af7ded9f55ae4a67a420adc5f9d11b3ad33
ff03e1:d58c14fbc0100e11efe7208dd691696025733e1786f1a7303b0633e07f661c39
ff03e2:e1c4b0b5be92471eec288db2aaec80fbe065fbae8c9a9a57698d7bd89f307031
ff03e3:af55b372ea64ff3080f31f8429913816deabaf390fc5d2ac271e9a9f62d8f575
ff03e4:a5b27d844a0ecb68f1d065723202a2f07c667de96b84e68a9af234669397d6c4
ff03e5:fe95a24e7f94978e58d99350ab7ab789774a987cd25187c128c191d207523bb1
ff03e6:f0b6b7598df2790471552632eba9cde6d349065fc6d665957f9eeef5a7bb24f2
ff03e7:beb51c8f452426b2b9e672f7dd1eea4b33d6c38f4ca2a96956ce24bd05b0c38d
ff03e8:4ff577fdde28e61e7f5ca4f5f42bcbb12be179700a4fef24489ce76848a08346
ff03e9:83cc50e15d169824aebd0becbffafe736bc55ae211bc3ee6338fb473b9015a07
ff03ea:6af5c4eac180289b94a77a5d231e3865ffe934f3e6a24bf487eb4e2bfd809a4b
ff03eb:00c0cba95cbfe1e270814275f32b505d6e5916c2b6da67faf4dd309ee6e86cbe
ff03ec:a66c97ae59dff9ea015e73c744ee5520745f101a395c497d19e1f168d39afcd0
ff03ed:985140919342239c89086b22dfcaa4508590b11a3de0a423e25ebc3ddaf8910d
ff03ee:95141a355a5a2aa3e011221cab9fe73810fdb5d88135864f03e4d852bd0bbedb
ff03ef:58e89f4f70410da00b41473cfa413fa0737ed2729f3ed77be29a7f4705377147
ff03f0:d0e8a51acaab9af82767e2ef16543c2cc635551b5de0dae25d6aac71e7862870
ff03f1:756aab900e3f5c762734b6461fc32a9dd341ea1d4a04283409233c39787a867e
ff03f2:139ac36bd85398bbbb4588687c20dc36827d03a5f42aadf87f02becc4be9bfc2
ff03f3:a4b2b47545559f5fffb7cdda7a1220e62fb74d1b7a9a4d4dacb2b2a839ce7456
ff03f4:b75aee9836fefbc446f288a2970b84fc60aaf9efbd2cb9f82f7581790de4b8dc
ff03f5:bc91379a21e7bde11b455bf1d51186331682805a4a353a8ee258f7a03706c664
ff03f6:69919d820edf582adbcf8e092a9284d901772ee2b419ea9de1f5872c791fc6fa
ff03f7:ea1f3bfb4d3296b467d4b582559d6518d676d5afc7d1c24be80252f79191046f
ff03f8:9db0a20c305541e15e818a880d06579876a9c901b8eecd968482c58d9ba7f0a7
ff03f9:8d83d69fa615aa2683b13d7894482c542b0bcf18bb92d30f015fb42471afbb66
ff03fa:358df39d764af9e1b766e9c972df352ee15cfac227af6ad1d70e8e4a6edcba02
ff03fb:c741f70f4b2a8d88bf2e71c14122ef53ef10eba0cfa5e64cfa20f418853073e0
ff03fc:93e33af7da3030530d090c9c55762cade7eae943f834349d1057a90eb67f306b
ff03fd:6a7b2aa3414039a663d5d8bbab8256a3979a84c332bf5e1ee8f6d0e0ada84668
ff03fe:ef66b0b10a3cdb9f2e3648c76bd2af18ead2bfe6f117655e28c4060da1a3f4c2
ff03ff:9dc946cd4662be72b3597050ee3a317d837acc7c0fce5154d46885e0fef48939
ff0400:d4c4caf9a1b2e20aaf77e93951efb6973a3bac9d261d6746aac4a49e0785aadd
ff0401:873f4685fa7f563625252e6d36bcd7f16fc24951f264e47e1b954f4908cdca13
ff0402:51101faa963129319a4a07753fb3bad3901cbacf6f19039fa0e05635afad58fc
ff0403:87ec80b7062053fe5acd4abe84b01ebf3404a64c6b27ceab531ea75090aa43f1
ff0404:1e13239ae04b971bdde653afdfc7324438b8e146c5c48a817031226c95764539
ff0405:f1b41392b8b7cd5a456b2d4a91b7bcf6ccef2294b8b6e62cff38f9c3a2796f06
ff0406:0ee00290c8a71d985e38beb84ecac9d029b55967119d47cbcbe347f164df4b4a
ff0407:05ffc64b8fc53b79f5b9c62961ebccacba1931d50f34d014e929eb002b5bd832
ff0408:9c624a017764fcba36358679804a75cace95f044f055dfdf02505f3b06017f34
ff0409:72f9af2158181baf16d60c9b4e6f4bd7ca8d2341ad48afdb67cb4c8332d546f6
ff040a:77cd51784a693d9482e7ea694e4053bcfd9df65580fbce14b2a7527c081803e1
ff040b:3995b01a17800aecf5480e939d9da44edccc7cf2935657c6179d5a1efa25d74d
ff040c:44ce97f5c957dd056d44c3e1bdfceb2cf9a7b428ed089839264336303bcac7ef
ff040d:220040dda377c944429e8ce913b7d81b36de34ebf2dc218d2066393d94863439
ff040e:dc9993dc33a71fd95808787d19a4b55704e601d57ebceacc8802c78b5c36f5c7
ff040f:8c0994b2aed0085fe542813ee03c4b2d732ecdcc257ae6453114c6c875933bd4
ff0410:ba425122f31d9bae7cbe1e7fa2ff437adf283e014333485f7691cb856aec776a
ff0411:146c1cf9bb7d231060d0fabd986e9850f00501f5a3b7b6ac42c51b38c8e22a23
ff0412:da0c4981f6336e06c129f7e8143b2a54aa85a14a63ca44fce2cddc69eee788c9
ff0413:f0043e9fefb37aea794e690437dc239d6bd2c5ca0fb58a12244555a1a8a2a01a
ff0414:cfdfef037cfdbd6bb0e311e9bb281ca60271c5dae2695312033806fa4b0e94b7
ff0415:1af8b4d49c5a7b6da536dea92fdfaf45736205afca2dafffaecb712da9c3ebd1
ff0416:25eed131d7193597e48d4e36536cc5cffbf9eb2042c62573ae8968d8a3695f1c
ff0417:1744b474101fe6a91936f5e60307c63da58b88405b045323dec8c8c00176af77
ff0418:5dabda046272eec89ecb95a6297dba910d0144f7eeb5814d073ae54a4a8cf646
ff0419:6539235a5a1f94180c5233eaf8a5d67102deaa16c0751aef35b3e67ce5607f29
ff041a:1c9d3e8e0cf1e4f39c734d19e479ae971fc3066c000353a2b6af32795a97ea1b
ff041b:efb44844f37ee6de3fb4cc8d2c0c832fc8feeba9506237e0d1fc7ad4574a4cca
ff041c:8265756dd5cd8a37ee61e40351288e4b16a89dd248c1ec4eba25aaf161abf498
ff041d:9ce630b35f8ae2c6419e734ad9d2fa30476dd9e7394b1e93b27f83f776a024ea
ff041e:ea423f1b3b1b529d1c7db9a21af87dc78de7259555e298ba26c63cf1275a912c
ff041f:c30bc9667e273937833c396ad85ee325de633f4fccc51483417a9c8a4e33b39d
ff0420:4b704cda80e244d4186844f0ef242b70c4b1ab4d8d8961568f28e12c89784f23
ff0421:7f814cd1454900ac1331364b6b6de06b87cc8cb9936ec583100822721057d3a3
ff0422:aafdcee5793b5cf4bf2d0c5f6042d8a422bcc33b3965ac6283d273cc69b48375
ff0423:97a718082b78ee7480979b2116d4ba0215c61aaa520b46ca6b9c2ab378f40821
ff0424:eed0a95e7de3ca53e4a6c72a86b3f164c0c23e380f8f6b79a349ef1784342c1f
ff0425:8464ffeb29a3ad17e9d6f46e48c5c727c9d7868dac0262bf256e20b3cfb55882
ff0426:bda4672a403ca2451c74d7e93e7a4e71a9ed22a2a8ccd6f91f8fe9ae0e6ca881
ff0427:3f034bb5704d44b2d08545a02057de93ebf3905fce721acbc730c06ddaee904e
ff0428:4b009c1034494f9ab56bba3ba1d62731fc4d20d8955adcec10a925607261e338
ff0429:e778f0f095fe843729cd1a0082179e5314a9c291442805e1fb1d8fb6b8886c3a
ff042a:972a181b60294eba07333b9c1982440d43395aba91d450ec0efb485aed49d5a7
ff042b:340ca5ba402d140b65a2c976e7ae8128a1505c29d190e0e034f59ccae7a92bc2
ff042c:d6ef3e09ebe0d9370e51f5c09a532b3ac70d3ce822253f9fc84c28e9bfa550d5
ff042d:2585928d2c5bfd952e025bd12e27c6776224cf752ec362d3031cdd49351844d4
ff042e:c5eb1a7639b9d8d70b4f82add80794175ee4b6a3db1861b38717c96fc1914927
ff042f:4d45039eecca114d64822a0aa80944d66e08faee62b1d253f140298769f227b4
ff0430:8e2d07bfc591b14fa314686e1cc8d9bb5f6f8d091c0595194aa2c7585b991887
ff0431:fe7340370d595a39ffe10dce2197447ce67c98be28f0330c8fc85dd03212486d
ff0432:1e3349cd366a93e59ef4152a1e483dac6076184c5d46d4cda00e6093efc9e6a3
ff0433:7ecaca4a3585a3b40e25574415512d56b57999b753017856f2ab15fa1f21f6d0
ff0434:047795785cdcff9e6e0ae122492e5b7bf08a9e5c49762e2bcb52747c69031561
ff0435:f606d8deb27c0401f34e7b6a37c8e2a51db8da026be58a07e854b686de74c69a
ff0436:9a6962cd8c21b5dcf1f70b39a836c7f397ec495f880be9b9b69b8b27288ecb14
ff0437:4e30f8004c18d3d798ec5a7734346b5a5ebe8d54423ce98257fc57735a6f738d
ff0438:8a023c08e4a1aacc925b34c5c7965a8d0527565aea130abb915e508cd33afb45
ff0439:52dde89fdd6f610473f9314c7a8b1ac442f8aa833aa5d773006fda758c9ff1ec
ff043a:dcb8aeb0053ba5c530f47a2be1d1e4f77b5a076e1d8a28f6d36c8f1efde761a3
ff043b:52b6c4b05b3c521774557cd53eea5956f36bc94c64b66d99e8a7291fc2fc9c36
ff043c:4c9e799fea626f5ed35d8f91548fb6a3900503099f32bc49dc0fb566b0a0ef37
ff043d:f3896f88fe7c0a882766a7fa6ad2749fb57a7f3e98fb769c1fa7b09c2c44d5ae
ff043e:574df6931e278039667b720afdc1600fc27eb66dd3092979fb73856487212882
ff043f:3ee0278df71fa3c125c4cd487f01d774694e6fc57e0cd94c24efd769133918e5
ff0440:115a2a45db520361a2cdf0a395c4a4bd8a18902eaa4036792825f846bbd76917
ff0441:0a6bc3e2024ac462f5d72be436ae61d033978ea8ddb63d4c5d6214915e69049b
ff0442:d70c597009af3a3a37bdfabea0c64108c7b83cd6c2042e8ff178a3ee8fe0cae8
ff0443:b408d6c82097121694b9b6548c5b4944594c081134f36c5be88d74fa34759d91
ff0444:e601477705341270fd120066bbdf26223e6953c4db8fa7ea197eaf5bf8343b25
ff0445:3a1a4bd6a62468578dbc91dc24705b276a837cc18b6bef1ff3f6ed0fe6326302
ff0446:2f9f41114dcadc30784e40fef7d6ee063a9be7a363de5737e88fa1118671505e
ff0447:3f5cb1531cb1223aabfb70872dc43d2dd6cc3d2823e96b458a9f8a7ec0265946
ff0448:76648fbc40cc4164cea02422a09eb4ead29c67f5e7dd74f691b7fa08043472c5
ff0449:70c4002e0df2ff51e691654903be742d09d5a74a84b15b68fbcda320fbf3dc6b
ff044a:93397e182492a7e7c582badfe04348e6fa985cba19afde16fd740ff03857367c
ff044b:a2e2c3d73cff96451325712e212fa15c40fd4f2c3f143c1bb619385365304c02
ff044c:93d931d5f95411998705b148532f4e16fbcf00f3318dff9b6a0765ed749c8fd0
ff044d:c7063a8dc668205e66153108fbe3bdbf6edb6f8ce5f616a369bef6324dcb6354
ff044e:1c4eea3a47abd122568eab547e06b52111f7f388662c246c8ecbe2660b9f26f1
ff044f:1032c6001ed664a0cd343b138bcb6860e2111011c3d5f06540f5be41147812a5
ff0450:9588ef74199e45acefcccfc0c47010e9f2a37a1dd44c61a4e1c6b334da5af614
ff0451:2d140f20b8a96e2b4d2f1cc5aca5e5a1e7dc56a7491e510906960f38d2d21aef
ff0452:3286691412f30ece5c065fd62f4392a4762d1e77815338359df390299fbd61ef
ff0453:c8a610ba9417770d2c02de22bca8c56a428af75e8e354efa36c568221ddb7cfc
ff0454:3450b6d38290c3ca5d7bb38b71495bbf72c6d0c44dba292245f9bca9843a9fff
ff0455:124eaaf26f570c4fb4d89f5d61078f15b885345fcaf0c57f3477d8c63b5ab26f
ff0456:931aaa1ec9b2ba0fa59a82302f4f830628c86d9b2d2a50a4d1b2ce895c4cc648
ff0457:91f19ce503c9fe7ff9587d8efbef7315aaee77dc2d14526126493b4ad6fe801f
ff0458:5c452334d9c9c9a2ea42cc77a7165e1795ee9d84eb70cb784b47ea9d92a582d9
ff0459:11fba4a7ee579c70e1d57f9f9b6a8c209e1219c4f1d3846f83ffce74e9e5e2ce
ff045a:ab74b1411ad23e2227fb88a2a9304a1a45a5c4840b3635f1036a46e8374279ac
ff045b:88fc18bd071be1fbc53ffbc801f03f5b2c4da87bba0c098e2b4808f19eab05fe
ff045c:32a4e554e363116fe48e22f01dac1736752a71c720f99f462d565022d3bad07d
ff045d:cb6666b32bff2efedcc4187df149a6d34a5d10b7165b9cff2a67c0e311aeeed7
ff045e:7feb9374eab08d392717c647436dae06176a24c010607fda1cce5e5f0106b472
ff045f:b1aae1bcd555e8a3d1e3dda8ec84e757c552655344ce3feebbaf98e895dbedac
ff0460:1e356823fe40c0eaac29f9ed5463b7b2db1c088b63ebb05876a2e631c1087798
ff0461:801c522d3ad138e4f05d467ea369c1cc276078bf284018d0525ebbbc5342c836
ff0462:f19d55cd08a3ea42bd91508073823174dd92370213c177f82531756da7508a51
ff0463:762538439509c411c437d3c567563e1378671281fc4a1464add031870843676e
ff0464:b65fe6a1bf2d52ff68b7d3e9d0f06b300a1c3f248309b70405ca7bdec054bddd
ff0465:d4a5941c7141ed1949a0c6ce9dd45a0ab94dc337902eb0a1209852738eebe854
ff0466:dc2728331312e75c4d7b442f3bdda790cb77a9d6ac854d5bce18ac43ca59909a
ff0467:bce7091355d2417a37f8cfe2ac8f17c2748888ba0eea90000fc980ecfc2d041f
ff0468:364df25cc88f6fb0202c02cd9b8ea02dfe8ac02341eff5a9dffc5be159ed5991
ff0469:e1e15d289697af3285bf34112a3e60bc11c0c8122dd2b9b3420ab2e5e57883ca
ff046a:a665007a05efe1889d66a40deecbc6c1a271e919006811fdb8dbd7e0675212d1
ff046b:23ecb03eec17338c4e33a6b48a41dc3cda12281bbc3ff813c0589d6cc2387522
ff046c:64e286b76063602a372efd60cde8db2656a49ee15e84254b3d6eb5fe38f4288b
ff046d:97d42003e132552946097f20ef955f5b1cd570aa4372d780033a65efbe69758d
ff046e:11c697878732056de17c1da134e9d2b6d23cf1de95b3fb0a4d18a517ab63230a
ff046f:288b35466fb8e228b98832019e1a7956ac3e9f154280cc97486ecc8e2c9cabc1
ff0470:7102d972c24e9ca68d0e6f9ff53c5f658cd9b8649f28ead8dbc336c2df504811
ff0471:8298fc42704c4ed774b4db310529260b524a9075252a1d0ab38e06f1b9a83499
ff0472:208388ebf99b12188852f11dd794667b5e3995a2767adb255e9b8f5d4cf50576
ff0473:05877ee5ccfe7cf1abb3c9edf3905b5f6142c7b7939d67e32411cf896327f987
ff0474:13f7b37cc1f8442a8ce13e7b4422217d8e89957cfea850c3cbbe75cbe561e774
ff0475:c98a8999511e2f60895053aff4c539bd1b6765754ebb7b353896b3f2974ed83f
ff0476:78cb512de48cedcd7134df57c973c1e1a07692b8f542a44acebb8bb776d55d59
ff0477:67add1166b020ae61b8f5fc96813c04c2aa589960796865572a3c7e737613dfd
ff0478:1a07529a8b3f01d231dfad2abdf71899200bb65cd7e03c59fa82272533355b74
ff0479:8b05b68cc659e5ed0fcb38f2c942fbfd200e6f2ff9f85d63c6994ef5e0b02701
ff047a:242b69742fcb1e5b2abf98898b94572187544e5b4d9911786573621f6a74b82c
ff047b:b6f6559bbce0a2cc91e507b5d7319e32487edae28a063bc73b6405e6c44665b6
ff047c:c1ad7778796d20bca65c889a2655021156528bb62ff5fa43e1b8e5a83e3d2eaa
ff047d:d79a2d5e03295c0e9feae36d021ebd5209700ab1a9e817a43f30fa3c66f78d21
ff047e:cdbcbef16e37237702facc4b55d3ab92a17cfa17835e13377aa4d2ba0fd47a02
ff047f:25768713d3b459f9382d2a594f85f34709fd2a8930731542a4146ffb246bec69
ff0480:fb6060848440aa4594fe8109741efab40c56732b26c67c36d6dc945bb2fe13cf
ff0481:a1448a015e1399c5a891812f0e88c6d847b221d21f9326a6626ba43a0eb612d9
ff0482:ddcbb4f3051d6e601310eb0e46b5bb99c5e8b99f7a539e367a987dea030e318e
ff0483:1f8eb9e9a8e066cc5b3833e06b3129764b622639d5b163f600e1c79120bf3eed
ff0484:440b37416f2de852ca386150d611ec0af31dd58d8a27f882815a7ea3ee6848ee
ff0485:4f35c6b9c100905ff25bb01c0a20ebe335bceef249ce9ffa1e11e062ed66fcd1
ff0486:338edb04fb8beaf07a10749e7f4e538de0715dafb6478d58063fb7c8bdb0c30d
ff0487:38f73647f1ecaeec0fc5afe68ac30e0c26171e9f232f4530729412408fd53626
ff0488:5f88694615e4c61686e106b84c3338c6720c535f60d36f61282ed15e1977dd44
ff0489:0e34cc35f66de0c06e1d901e2580961542ec2e2fab1757837d09cfe36547966c
ff048a:93709b5bdb0c768fc969fb4965868218d6de86a6a26f813b726ff46976607c64
ff048b:624ba4272c896cfbe55128febe6e4d6d248c23a1c8db32d1789c811872f6fc3c
ff048c:4687344f4713abd03dad9199428c6ad6a5614462ac3bd79fb0f0c1a56f4a2065
ff048d:d9d81c01505db193710210d9b427b65329efff256135f6fb2fedbe53e593bf02
ff048e:7ceb9458442756f40a485c30f2baf00107c1e9ee85db02fa00f41ba5844364e5
ff048f:34d8a73ee208d9bcdb0d956520934b4e40e69482596e8b6f73c8426b010a6f48
ff0490:b085d70b964f191a73e4af0d54ae7a0e07aafdaf9b71dd0862138ab7325a24a2
ff0491:d947432abde7b7fa90fc2e6b59101b1280e0e1c7e4e40fa3c6887fff57a7f4cf
ff0492:8d25cd97229dbf70356bda4eb3cc734031e24cf00fafcfd32dc76eb5841c7ea8
ff0493:349dfa4058c5e263123b398ae795573c4e1313c83fe68f93556cd5e8031b3c7d
ff0494:37fd29c701d6977998f205153ea8a4c2e996354df072d4984dc5d8b1f75a2b61
ff0495:92ce7ea7424b3e7a2c14c26e0d572adbd556e05e2b2a8bd3761c695254255856
ff0496:4759d6f4ed6df0e08fc4ca801986e2be10594dbaf341b4c45abafa3748887d25
ff0497:422f9d4e68134e362b7569e5298a173cec40c7c7274b2263a9bc8ada1d1a23fa
ff0498:dbe2d63dbdf76f71ba631354e16ec97c16e016792aa3b9cc9d28c582cad489c9
ff0499:164e0073a75200a5816991bdc17c526eba21271f71357446984ed2c80a59fd5a
ff049a:3ed13f9d19e56f5ba1492385ca813f7dd63bbeb3cf5c56db5c309cf4eaa90171
ff049b:0d2cc7e6973f80fa2253fb88828ef6acbb3b95ffa77c489650c356735f54b706
ff049c:f82f8b50967c0a52e9d81b79a90ffeb8e515b7814a5e5de2f26b0f6af6fe7531
ff049d:6ff2159704d4e886859a140ffe4e33471e514217430b03c4cf6c85c637f7ecb3
ff049e:002393fa0a6825f77ef686e208620b97177791f02f07db2518480fbe37ce7bd8
ff049f:562d6a5b4b067465ffd0fbfc9bb05755cdacf55b5ee5c6f910b8b53db128f57a
ff04a0:cb5535486404a82e5079af0f9ccb7ea3dffdf9da4fc925b711062249e6502851
ff04a1:7752ee9d27528294579e449be6ab07d720bdeae3a5e39c05af7f26c2d431beff
ff04a2:cb0bada3ad53a99b4b7a96020c2869a43e2db2d0183263f3303ac7e41877a665
ff04a3:875fd03c6c1aa2e80c8e8467e99192a3a55d51b1f9dabae1e6821f56c4e1e783
ff04a4:6a7204d6f6e852a914cc0ae45afad91fa28d1aa4eca3844097a929a8e11f3a17
ff04a5:1c8cf4171ae81798eb7c85da604d8c21076d769119471e5b476c91858a4850e9
ff04a6:8cb67e8e76de03a83b9a4daaea595f70850df42a6e5602444754fc52f4001633
ff04a7:2e022ff820f520a42b06b3f0a2434e05f560680ecb2d1de329a27e351d359a88
ff04a8:6e0bff069a26994c15de2c4888cc54af84882e5495b7fbf66be9ccffec7489f6
ff04a9:aaaf2f29ef524471cb4f15b72de6a5542629978fb5a914a611955c75ae5ef3c3
ff04aa:e59aaa816009c22bff5b25bad37df306f049797c1f81d85ab089e657bd8f0044
ff04ab:08170d1aa36453901a2f959245e347db0c8d37abaabc56b81aa100dc958970db
ff04ac:a9841d2e47cbe6d71d8fafdf38387f93f43d76d792504efb17a21020c58c0b89
ff04ad:339e6b92be5459f26a8dc3c5f3720933c838e236601b050048c047a123e6f8e7
ff04ae:199ab2aaafff40401e0a3b7b87ee9964659effa94a1fecbe918ae136e4b4e0a8
ff04af:b268d16934ab5ba232f179cd9f5c7fc07ea8583a56a9a7c1d6cb58fe0823bf5a
ff04b0:41c897473b0369fa74b1f4f9d7f89129485c1a305c0719a867dc8714e0870200
ff04b1:603db707a584003bed6f1d43dcd4eae13cd18d798e827de2f3a31f3193fc0dac
ff04b2:81cd03067252ffe849b240dcc24566678677e3f5fedc4c540d7a26cad2c081c8
ff04b3:9bfed3d9dc95236bcffcb35d4b120db0e3867f62b1fd015a928da0b303966683
ff04b4:74eab573da7db195097be0e90f334934c7a4c89e8083759db4333a00edd243d9
ff04b5:673e8feeb1168277d0153111d20ed38e9da51f440be7fd50b218540937741a48
ff04b6:c42a4d8c0904bb211906f43b441bbbc9b5a003ba3611879fd34ae576f7c2f764
ff04b7:d8cc89c6aa6b7452881907927c81e66da01a7598cf7674e4e2e133f16546d5f0
ff04b8:728e4bd2b399840e9d437af975b0198910b4129b7ab708cb5c0b445d3b04d999
ff04b9:b84d72d3742485c461a27ce05eb91408ec0bfaab5441fea8a223ee9bb706a68d
ff04ba:987bec30935be68fa82b01a7ad4db2e6ccb7e869f28d352d0ea4d66eb1fb9334
ff04bb:d68e4629f757689782dd82c0273ccc1ad0bbd1cf929f4088986ce2fe787a425c
ff04bc:fdb351bda2d821c3dfbb924a12d90d6dc760d5f6200144529e502e467bbf9ecc
ff04bd:b1d1244218c903b64ebf42150c5fd891eb5b663ce6f20dd12e8352dd7d1e6693
ff04be:544a6f6299756ecade4f7c34811054181b6a23c0ff83eb0ac1a28cebfe0dae3e
ff04bf:b4983513478ff0c1bd43d31d5b81776276301cfff58f50cecea80d1b586c2b03
ff04c0:a6d481bff312c26fd7ef617f43f40e18329c18455f99bc6da267cb2a79aa4f91
ff04c1:5163fc5c1af06a252a4ae98979232f25da210a2002536f370b429e0400602b37
ff04c2:091ab5ab6539a6f55d2363637da0a3fb976e6db8e55d95fb4b39e174f2a918fd
ff04c3:23ee12a8da9d38549c54a32bc1e4a18baf1570488107d169ebd734dfda330b0e
ff04c4:03b2b514b076931079aa09e784150d4fe62cc9b2a071eb601b125292e50576cd
ff04c5:306bf8099636a44fffb5eedce6e30c0f36c7d43f6cca5a2ca3ab71668f353320
ff04c6:868a41400d425a938d7ec06c29097300b12706db473b6a7950565f98d704f196
ff04c7:5460496ad49cb821d627dac8a805129822bab242b929a0e3195d705761d1d16c
ff04c8:e755ae9c42c1315f27dcd06451c6abe0bc6aad6eddc2e5635cfc4918192d344c
ff04c9:54a76847d293acb8fa1d885de4bb449956b75092f9623fa43441ab445dd5728a
ff04ca:ef150b1a3371475c8b3ed11dbf93bf90840bd5395c6b5fa6ae3bbfa746faf55b
ff04cb:36ba70baaedf637b4c16b54651aec36059daf64dcf6cae0d94cb88c2cb4c2702
ff04cc:2697acb96a49be2bfc5c06c393949f0d8e75106ad6d4c73e2da172a90831a85a
ff04cd:3818995b28a090d83a61667117d50c77c1f1dc7a137680f2e55ce755314f2d0a
ff04ce:17f08a4f5dc38c49bb17dcd64b2ce742cfeab99be5b67dbc14c2e896771c60e1
ff04cf:0e5b8040b3ab60a50d2d5fb11e19aeb2e45b564b335b79d773d42b81d8219c75
ff04d0:0c5a09db8aedf7d2d1dde14dccc2db6ea959bcf6f010360d836c342c624d7e0e
ff04d1:06bb567771c426914c19a638edc18008f5901b92814a9774bfe8815bab7ea6e9
ff04d2:a6e6145cfa7322b22dd6fbaf1df8333788db79f19b11b695cfc907b40d296908
ff04d3:449910a3f4aaa81daeed14a01cf87f324fe880a879ddf7828e55c477589620ae
ff04d4:1b8348d9a063d8810f7735b3d205c45dbd84bb3a87c6743fe3228630dbc2d73b
ff04d5:3f61f80c7cd056b8493be44e99799a0bb70f01ba62f3d51f646bc276b1b95a31
ff04d6:7194343a3aacda629a24c50b645f9f0cc4e51942779aa0720276a94f21bf55f6
ff04d7:d95d0e8eda79525bf9beb11b14d2100d3294985f0c62d9fabd9cd999eccb7b1d
ff04d8:3f99cc474acfce4dfed58794665e478d1547739f2e780f1bb4ca9b133097d401
ff04d9:68fc6237c4b8722a1bdfb9583f728840a18bfcc3d6c6e1d6b0a307624577dbd0
ff04da:5ebd9874e6b88da38f4a7b9566ce5d4df05e0c224d94986ad8cc5eba004a0c04
ff04db:a847544cc3cd54e855ca39780c2162431f5c8e327ec66d5a43cf266877bec50f
ff04dc:863472ec79db54077114dade720ce1f7b41a233748fc6773fa86520f0b9aaa21
ff04dd:0ba8c0d459b76abc0825294f565e24f4f169d4a4819d0692d371522d297724b8
ff04de:69729b8e15a86efc177a57afb7171dfc64add28c2fca8cf1507e34453ccb1470
ff04df:28506e33f55a6072115f3e04c9bdbf5af5312ca8fc132508b97ac99fee0516e8
ff04e0:428b87b8061a79aba75877fd0383adb831a1459b86bc408ce7d8d17b295b75bb
ff04e1:8b6ccc3be92f0121e6494ac704bf0b9b9cebba2e363c8e8122d90984d3ebf386
ff04e2:f5f1a8c04e5cf0fdb678dd279994463e48508c4349643b0d92cbfd7523f6c40a
ff04e3:86b109232c19ec514f8cb26788e65090293f96dd8d2942017a33035ab225d5fb
ff04e4:9ed1edea95aa5b72b513a3e41a1ba0d2efb14cec88891e34d00495c95556605c
ff04e5:c8025f9fc65fdfc95b3ca8cc7867b9a587b5277973957917463fc813d0b625a9
ff04e6:699ed65bdd3d5e790776d165ea7a325b7aeaf419647921a92ff28bb0680d72ba
ff04e7:5d270cb4eff587ad6cd17cb2b60d9084a153d77d2aa79a2cb3db1ddb904684f5
ff04e8:495e6624a15340c4c74ab86037748ad62d1ef4f14e7c81ab7cdb629be1404757
ff04e9:1e29690f957f64ba9c3658a31055751aacd4b440a9589dfa1d780fe07069db52
ff04ea:d889a2641f5df941353817c87a5cd0d9cdaced3886240bfbd937329e94d3a45b
ff04eb:f9d4a6c011e9c6a8f5a4cf7ed0416869c7238ef93a56161ea6ca3d8b41716097
ff04ec:1316ed42a849217d51cfb4de1a1418a8d3a77902fb305d3024f72d4636b82ff0
ff04ed:28101ee3cd2ff6f225fbf0ede94ab50d6762afdbab964f7c9d3ccf7f02ee9838
ff04ee:9fbd886945fb6cb63eebf11077dac980e45368d2458ba5ef0a8d727046fcd292
ff04ef:1df929d90b3ad4ef94d36402f483462e8cb678495c687022423545b19e2f0615
ff04f0:ca623354a31c7878815e0d901fa47e30d10a61f6945d3cbefc4757f447fa8aea
ff04f1:392377a719e3e65a40d8651b92361db95320b39ca361072a3a3cf42c66e00dbc
ff04f2:3293500caa507b1e920a441f277badcbb75002caec6282d23a3578f7817d2380
ff04f3:2d923f67980da53aad5e5e6a61baad9fc645dd208d76c51c8eda5c73870a8f95
ff04f4:223ade0e45ccc4becb255db009df1e239aa5d71b17cf3db0a582c292c25ecc52
ff04f5:46494e30379059df18be52124305e606fc59070e5b21076ce113954b60517cda
ff04f6:bacde0463053ce1d62f8be74370bbae79d4fcaf19fc07643aef195e6a59bd578
ff04f7:5aabffecd4aaad9fac8aa5eb5301b5beb1710c865416a247c73db52dad5fb24c
ff04f8:979f6084b788f6d102c978d9ef1da4ccc9165c36981a2a1a3ce3f450ee4880e0
ff04f9:fb8cc8c2ed1b384de459f217d54d3cccf0890ec58aa9d97c128ea3218a426325
ff04fa:56800fda0d452dba2972194ff6de72147d0378887c60248330bb801795c687c6
ff04fb:7a4e1d1a4c395ce4ba22d980c9a8158a204e83ea47e2a51ff214927db425a5f3
ff04fc:f1e12c0c4ac7e564a1ff55ecb0bf50bd42aa0c91e17ef24696ca7296807f5c27
ff04fd:778c516daec700ee58b3581e411e5c0dd478663a5163a29895341507d6e964dd
ff04fe:8ab3a0acf289e6ef754be449236843d67f45c191bddd66484b85e6e60556a9af
ff04ff:4216527163ad2caa825d3bf48f61a7661d0abc89b58ab76b23a1e10999f0769f
ff0500:7ef3f89456ce636557b20c5dfb37f98c253a0b660d2e9e5e7845caf9c038c7c1
ff0501:074add7f1e73eb110ec8e2b78a92c51cf5a451135b6f7defc019ee9d74bfa4d6
ff0502:d16ba9acb74fee4aa8087ee482e86e7f6f5f55fac5025639730753fe1e705e3c
ff0503:0587d6bd2819587ab90fb596480a5793bd9f7506a3eace73f5eab366017fe259
ff0504:f7a9a1b2fd964a3f2670bd668d561fb7c55d3aa9ab8391e7e169702db8a3dbcf
ff0505:52274c57ce4dee3b49db7a7ff708c040f771898b3be88725a86fb4430182fe14
ff0506:371a00dc0533b3721a7eeb40e8419e70799d2b0a0f2c1d80693165f7cec4ad75
ff0507:018e13f0772532cf809bd1b17281867283fc48c6e13be9c69812854a490c1b05
ff0508:ef9296036a6d7c986c8d59db936093e78e85c70aedb4fe7a54ddcaa821031c72
ff0509:c6270a150691fbe190d831f5139bdfeecf7b298b4fa0ca17306a69d7e91e7ba2
ff050a:e5a1c1919e3beaee5935a8485ddce0e3f01a2618db0f0793b3db3d9ac2d967c7
ff050b:97a073957c5812725757672f222690655a1407d71011edfc8b2fadc5128911da
ff050c:701317250210ab91280527c3b436931015b8dcee69a6893ada4ffad25a6fe44f
ff050d:956ff9cc914874d9caf9655bccb696c1be49a25bf928d5c41c0f5395a135d8b8
ff050e:c1468cf2254e6004b24696aba209d1a30ba6e2dff68a9a4e32c6ab414f90c8d9
ff050f:e46a392204a8dca342a71c1ca9a60c9185b9a930370120c3b9c7e3856f0d8f3b
ff0510:08e7eac998a62c4155cc4cbc5eda32f5b41a12c012f29ab3433bd366348149f0
ff0511:3657927290b61f6cc9812b002431539b9734cb65a968576750c76bf24965e96a
ff0512:bdbf06ce9e56c4507fc24ed7fe1fbebaa9b6c83a5c6d7c22c39911d9f5125e5a
ff0513:12976558b68e8e1eaa79a629a8e4d17edef93f5ac30de6dfb0cdee389d56d156
ff0514:1937b9bf662fb578407b77ab87d8d662b16327cf923340d0f72d951952b19c80
ff0515:fe6b6f9e44b670797d52e5f16ef1bb10b49eb3ad662522fc632b37df9a5044cd
ff0516:d3419986a48765825d13b301547b27dc56a0ecd309198afe9a7d7faad64969aa
ff0517:65eb972ceb69e84a30446a2aad8b3f79f0e8044270bdfa2e9b6ae5d2ad55189e
ff0518:49263d4ad84f392d7e92c4c2f2240405cc86fadf12b6ba60a774513c93c10186
ff0519:c627355d5d7c032e8d056dfb252ce6c6c15495f7362d47ae5f7c92afeb3b62b2
ff051a:496f7549918ca64448fdea1ba605ae3a8eda377ad21cced17e798586468b1a01
ff051b:82a1bba2ebfeaeae6c9d34e841a1a896377fe2d037dca8a9deff7d38070398d6
ff051c:08fc942d5176e568acbef9c595f36a20de6acf9ea30c6f5fcedd48216ed5b070
ff051d:481e582a206a7d7040ccda17cf25d349785a2ab94ed7552ab254dcd38b032ec0
ff051e:d77c45c1587731c4632c19d6f3c9fe832626615c879ea053664a4b26eb2293ec
ff051f:5ea3857eacd4c7ca5acbca9c4627e26f3072038d191a29d4c3f9464b2e5f00c6
ff0520:4d55bc4abeb7d37fab57e573acce83133e36212c864e003fbcb30b5fc248b011
ff0521:5c64b1731a8138dea7d11c9ae8622891f945eba46825e7abfe4754f0a6011af8
ff0522:808ca1abbfe2ff1a9ac71887dda71ff6fca6c3b5224827f547515a4d9f7af209
ff0523:2769381532d96183ed39bdc4e323f3c520fbe6acf3bda30222239ddfc44c8380
ff0524:659c0f902d6059fbd1fca528839f20604b80c74364e58f9d48a2291f813ed82d
ff0525:f7b09eea79096a4498f6a2b8d6f1183228a3769ea988050d1b32a380eabc4f9e
ff0526:ada5a71af2121b569104be385e746fa975617e81dbfaf6f722e62352471bd838
ff0527:e7fa0f67c9b6d886c868408996dbdfc3680e8b9ec47628eefb4824c23a287693
ff0528:d793d934dd1b9ff9f6a76d438c760ed44b72bcde660b49a77dbcf81ec7ceb3a9
ff0529:e881d3b83c3bc694d7d99f92de83b2bff5c6ee2d9871a446dea107d6397565fc
ff052a:d3ed3fc40ad26b52e001e1e18f4b9449529deb75a81d5eb680d7b62db23ba96d
ff052b:5546a52504fba74f61ffd4890067529ade3b9c9d07e502592831ccda9b369fd3
ff052c:46319c69041db9a0d93dae802e3002cc615365931fe0976d392e8863e3f3be31
ff052d:9d433c237c3aee7a676c9a2ed4eccb9e40ed17914655571624f0a89969b634bf
ff052e:93c176167eca02a1b262b16517ac5fb5fc25d3568d97ecddd04e3a6126b6c7ba
ff052f:a5c53cf6843a395e6ec244e9b27d58413295428ded97586fd4f67aa4ab8d49a0
ff0530:4e1ab9f0122809e2a8e93133187afaf26e71c9c3bf86971065d578fc4c08af79
ff0531:7a2311b472b99171164ffa0bca3fa7ac9ac46d035657bfc1ea133095c9703933
ff0532:c68b6c455593e7ce57383a736517ca46fe86641e46bdfb25c12e41e17de53b59
ff0533:a11c3bc528ffe2bcec915a5b3437d4269ad74156e0166b47a1d5f141735104fd
ff0534:bc8bbd7d279d2e5f070bcef6faf3aab1bef30da3eb2875424295ad147f2aef07
ff0535:b6d56f3dd26ac844e57c8bfe9054f57061350a90894b99cd9811e9a545fc84c5
ff0536:988d6b2d87baf43821c4d304be2b0e8f325dc17b7a220e934f5c5b7badff8e1c
ff0537:07cd9aa9064a9b94c6aef8fb784c1bbc1beda08acbe86878d781a39167626cf8
ff0538:f91606d1bc52c610136caa856ab500c48c3b993bac4808cd82bc4b78abf24156
ff0539:77b82cd8644c4305f7acc5cb156b45675004033d51c60c6202a8e0c33467d3a0
ff053a:b4585f22e4ac756a4e8612a1361c5d9d031a93fd84febb778fa3068b0fc42dc2
ff053b:e6be68ce06fe0da0c140f1aeb00b67b636c5eea9422088929362375ce086db39
ff053c:98dd2a75f65748f2667bc4b079177813647c17edcc6dee92f1f06668be0f1a3d
ff053d:575c09b07a001ca0ef6b3b1c5730bfafebc7ad9f56a009f1966c32f08e659713
ff053e:50e27f90eb6af495b0e6eeb655cc89444c27d3c95b6823fa02abdc95f1636ae1
ff053f:4acd8dc6020a545a858943a553b5e0f3fc5b859aea1746650d69cf1210f956d8
ff0540:7f55276114dd8965dba5b10819fde121c20b11c8484977fa38814423ae82ac0a
ff0541:ae2110f2354a9db0c53aa6e9139faf0dd2eb01865a6671135c6ff62d9f3848a0
ff0542:91dc2881f6ad0a0013b3d44e99361a13862f9cb7be6220fcdfde60e48bdd317a
ff0543:f14a7d2427ad0a01b4d7fd79d8d50772d2526e252425f8a09c3037fdfa635f5a
ff0544:0ac9fe8438b1fe2fc676416dc976ae8faa977bcc485d7ca69fad2c7ebfdcea5b
ff0545:acfcc02431f4cb82f552c43bbdf8fa0214a5315c73b82caefaadb104de251360
ff0546:12447c4656ddeb4882b48556ac8f15e17e372afc72c9f7adbde733cd7dc2100a
ff0547:babbca986946352cf9bf382e880652f4e94dbc4fedd0f1cc21fa9973c96d65ab
ff0548:2a6286c3ac09ae6cd3748b24a33f30fb93da991f883f7002824b14a914955855
ff0549:e3f355bb5ec113cfdc5e1cd2340c65c26df4c69879fef980036ecf42fd099372
ff054a:19098eff9c0cb46e1f06adfadd1f3da5712370f7173334598137d4a555fff047
ff054b:c631ca8b9a1259455a661e2c5388cd069a704bce54fa5efa706bf0b0962d8ff3
ff054c:e20dff26f3c3963f3700bf2e108f1f9e9dee259c24f8afd0dbbb6fcd9a1bc59a
ff054d:bd966ad6e8fcc2e16b57093a9fa2b793a4a5c517c3c4f8b03c33d4d8f938fa3f
ff054e:3c72e1f5a0a01bcd33b1801eb4044995ae4c9b1ba8b7db513675dcbf7f82289a
ff054f:28bddb0239d2d5607e8de8f223b5f7069cb8d1a278895d4c4c571e7d0b697663
ff0550:161ee5386329b28a27ff405736552a621d5a844a43811e3623e52eefa0ba840a
ff0551:7aede5374eca9ff34c5727c10db982222d753157797449b88364f70eefa0c24c
ff0552:8f3e5d6858b927d284fdb85a1b15875cd78e63b820c20ddc539ccd84b0c1a6aa
ff0553:f00e616b59ed06e6cc9717d039f7a1a70cb3d08e0b6ad74653670cce448c61f3
ff0554:623abec6f85a7028aca10f5bdc5d81b56b6314df28743ffcc84eca32f35ae846
ff0555:52999873a3d12a4571db9a160576a9d951ad4e4a7da31c5c10613805e9224325
ff0556:38f58caf650ccd4f6027d1c922682891a165fef491fc1d333fe8a9c851586d48
ff0557:785fd32364c457e2aeb4353aa95808f371aa8906e11c40e13c338a6b3ee73be1
ff0558:c97f2f6e6a8adb6ecfe4978f08ca8f6f0123a94784522b610adf6ab51439fc62
ff0559:bf97db75c13615fafc6d1e75edc3fe331c49806969a5a83d78596d1a1006aff9
ff055a:7cf634f5fafe9ddcc88b36d6b1e7ebfb7078034d64419e7c678335e56d823421
ff055b:0d63204836ecca89efbf4776b8ebc328008131b95d70a927afe6f0e1e9aed488
ff055c:4f4d8cf5e75ff7addf677a026a0efdb243c202de4d7f446040e5cbea2ce03d54
ff055d:3a739e1902626352c3337e94db2075998c456cf65c95f5a9632b12d0b7c89dcb
ff055e:0c37d499c45792941c62f1e19f06e9755625ce11633a2e8db869c7ab2d78c319
ff055f:d158333e02b10c80f6966b7705ab79570b17da38b1e392145940ed7e67ee4fd8
ff0560:5251e2a5b3a42021667994b04e195b693b9b71b752267c44dc310a77979bdc00
ff0561:da4792604e554a3894efc97489cc4b64831b2cf7e5512b3395ef9963d6efdd7f
ff0562:0d4d3a2f6dac222175ba1df78b4817b469095bf02f47919512353115902265fb
ff0563:4e93bcadd5d4e95331ae362df9c6066cca7f942a8fde4d3ee011de34074f5840
ff0564:2dfe47e144abb39f9fe451cecd352d9a9bd28982351e8b6524feb101dbab1fec
ff0565:d50b20adff959bfbee83b6fd1fab36fde7941b960cfc6839aac63b9ffdb46413
ff0566:735cc386ec1a82e657a5b451c94959611d3c7d0cbb1fd9d9edb42c7192f8463a
ff0567:afdb3c396d85d19fbe58206df0659eae614c4ab18f5ccf20b783aaf0bbe96a03
ff0568:45f1854530ec037aaacb4b2de9b4d0fdbfc61888abd4ee0414183d99e60437ac
ff0569:7b063a9cd48767c475aa6bced4667cdc56068f8b7b895125bc4eb24682eeb606
ff056a:cb2c685cb214dcd2f2cda6e2c155aaf21a7e134bc0bce808b1130c459125b0a4
ff056b:15b63cdd772a8d42dc5e48174c1f7e3d40fc82c478df3a6443c7bd92fbc6d5de
ff056c:a816afff746ea0f0a0a064c0432f9d2b7d0ce79ec2d1e9940f4a186a25182284
ff056d:256602dc8a8041b2edc0cae611a6a98d9b39ad4de3e19f62dc0a0a1958b72271
ff056e:398dc562dc098cf75f3a151216e583380c279444b0d63e766d9fdf6f47d04c60
ff056f:5e2a73ee6069de65322dcf0430176b385f5238c296ee4392e7ed7db4be908a40
ff0570:7cfe34378e73069f3a6813bec89a0e47693c21ae26a3760d50cdf4d05e40d1f3
ff0571:75e328643bfe7642dd840e3169f942c66bf04919d8a7fb0af96602612003c3e3
ff0572:c5b4abbd3bae38114a3a823a8ac4cd31c45465b7c1cebd84f36d72054afbe8bb
ff0573:b67e4e92286e168a916f3dbcadc3f0b83dbc0adbe43f995c1faad316ddec75d8
ff0574:938e52642501dd16e23d8aebfb97eb3c3b2562f50c324144c390946b29684a7e
ff0575:586a5c9836d9fb3be863ba765a7966d940297fec7bdd488016c7aa1eae1f1d51
ff0576:108162f2b35ed71c6ea9502f94b93e9754789dde871b2ac26ce06d47207a95cc
ff0577:24e7a0475697793abf3e0ddb04d542ffe7c93cc71d19f6067144aca89a4ca678
ff0578:7ba8f0bb49f501e9bb72e3a13708c6a933140fdc65592a37acde66ad07de607e
ff0579:619079f100a6bfb65cb2e98890dd0ac492b64665e254a66a529d8f5917d82ab1
ff057a:1c8846c406ac6294faf0d32a5a14e79c841385a57f1159b61e9014605e37e5e9
ff057b:987ff2e3b25a3a14cb843d907b3c7f007c274921afc10017f85d4fae7b0cb8b6
ff057c:a36c1cc623ecf3ed899a9ac14fdd5620919858e621e6877e01ef50da1db6a3ab
ff057d:6762522e4b57aed0960574ab061f79eea068c5ae3d815f50a971cec4958a92b8
ff057e:3687af02c49731ca34fe4fdb9b5e5e0ecacd8a206956f19afb38203ac5f0a567
ff057f:7fd28377c87c898e9094c93ea00bf107abe11db80b3d85e2b4a662697681235b
ff0580:5eaf05cfc9a017730d01e6688d6e39710e01fde374e74b1b25d3a48076ae5db8
ff0581:98a0c3ba1899258595d04f15d134c5732e864b755c648a48d1c17f0a260ef5a7
ff0582:0181b2b6173179562e75632344037ca523018618a7f7168269a3eb85367ff75c
ff0583:e0d3226aeb1163c2e48ff9be3b50b4c6431be7bb1eacc5c36b5d5ec509039a08
ff0584:be4b56cb5056c0136a526df444508daa36a0b54f42e4ac38f72af470e479654c
ff0585:2f0e385864d2dca8ac7ae48164287bfe45126c6bcd92e91bb3df1250c7b2daba
ff0586:34263e9424d819b94bcfa87e69dd9ef43205d4e2de84a53497314063d822969b
ff0587:be89264a58313012b749603c9bebc3cd7914db716a49e5e0ea97e43a3883a5df
ff0588:dbaf58debfbba1de8e04dcae7a2c163b09d39e7e732e91dea8655c2bd732ab00
ff0589:bcfd2614e42d63c59691c3ce8bec792de2fce89ced4f9c460d0a848573074fcb
ff058a:5ee5aad704a8b698883f4029720c8fa1cb79c9fa3463cc24340629ebe6c5a62b
ff058b:d6cc57b9260e9b012dfac40a81bfc022b92d91fa49b7c45c59df86702aac2906
ff058c:f1ed3b35c92fa5daaaa3dd45f99eba3b823a2fb1c24a89ced1699d95e02564a2
ff058d:7edbe6f8c49a1e3988caadd438b72f07b6af9ce751cf5835163161d63cae4ddf
ff058e:c068d776784255772bbc6ae9f70a536a410ad688a50ddeafbf66bcc5254796f6
ff058f:3e1479804765a62bb7bd4f0ddebb55a946a2063cd2882f05461b1754f1b667b1
ff0590:43a70e3620bc452339d878aa68f2e5358ac4607ac722c4d77d3c4d2c204f7f71
ff0591:11437cda7bb45e41365f45b39a38986b0de00def348e0c7bb0873633800bc38b
ff0592:2ffb7f813bbbb3c89ab4e8162d0f16d71509a830cc9d73c262e5140875d1ad4a
ff0593:02bdf96e2a45dd9bf18fc7e1dbdf21a0379ba3c9c2610344cfd8d606fec1ed81
ff0594:ffe943d793424b4f7c440c1c3d648d5363f34b82dc87aa7a9f118fc5dee101f1
ff0595:069df2f8919d9209d0c524a56ba1181df6d1bbfc4aa61c9f01d092e2d5c3a1fd
ff0596:eb89d3087d76912d7616ac99c73baebac1fb8e4835f8ba15b543f7344a4c57f1
ff0597:81473e1b18a688776881841b3ae160b2ad935ce9e8d5832b8a26256448db7379
ff0598:598d21250dc4002fd7f1fc0ef530633d4b1687d8597c0a7a86fdb0e8d70a404b
ff0599:1380eed66b2c316612d5f6e7ef68c2d3460582fea94e00c6c27595f91934e3d9
ff059a:0215311bc182d59718822b45ddf10213ce2661a93c3c2d203dec6567de44ae3c
ff059b:840e8dd1dfc9c0c50d29ca8512991cf2ed7dcddf12410375fd0a5d47f8fbf576
ff059c:293dcf7a9e918a33beffdda6469b614a077f02f905f7b599d4624ac7c68c6942
ff059d:eb5e6c1ae30a0f9b8c5769105ba9d6882e4accba5e2f2f72ac388a2faca0fef3
ff059e:f06e2c3d05af608c7bacb6366f7a47a017adec22f712bd417335396cb8b555be
ff059f:12dcff9b60269e3b546c3ffb7e74ba58eb7eebcbf5956771f784f7a582c2ea7a
ff05a0:29e93053769d4d1bab841b8f5c2603bed5e0b82f339670869566892146e89141
ff05a1:89578d72697ac25abc6f6d382387443965412ac7448f103c9b1d11ab63a555cd
ff05a2:1005370ed276b0cef39244e9e699ce4807bf9ade05bfa59f263809fb4606b72c
ff05a3:a8b2a4518a82a0cc0a60b2fb88b946557adb4fa58458ec7680a77bb0e5334d8d
ff05a4:e4c2d8c6e54ece1c996a305972b1ae0b064f105be06cfd7295fd2dae33b97e1a
ff05a5:e6c18d6d008c712b3017de1ae7659418983254b01de4895ae91f3b29ff482417
ff05a6:e68c3376f010219cca14e337f33183ef9d861e573a9d76287f3aaad4d04fa38f
ff05a7:0c92594bd394b4887a1d66ec5e631ffad3ba4b07fe2eb6d15d2f5fee4c90c454
ff05a8:0ed5aa0061d09b703e1b3150fb6367870bbf245cceed4fe08f2dbe4201723a8d
ff05a9:4006cdff6d8d52dc090ff5382b9c30cea8cc5005df2d5e8203cd67921797750d
ff05aa:f5d4cad53b3f2ef39810da6d3cd5ff7663f4abb87738827ccecaff6fcc3eafc4
ff05ab:b915b806a8b7be2e3809f2e932996e7c10cc82691864a89606bd50080dc2eab3
ff05ac:15e77c59404015659ee26f92561f007aaf53986a27926f0e707585c2a7f301b8
ff05ad:26ed3bde1930d8c53cecd1b3d50b0d7bfd2f4439c9edc8d708761ed6fe5da0ab
ff05ae:5266d7165119628f9559a1565060e2cfbf21354e1cb72ac66c755b9ee9f1902d
ff05af:45580380e4bc0d9728c9f3098ad7b60ab27212d0ff142020c5230891ab8471be
ff05b0:165aa432316aa826cbeb1e7a13e5e96eb9277af0105580a7cee5210f0425e056
ff05b1:bbaf546f28c300d906faa761415d97129b1d772e498b17ead67e3aad4439e3fd
ff05b2:1a1d59b3cfdb8423a6e2677ef15d9fc3d0da9dccfa637f60eae6e9b7c887c8fd
ff05b3:0e5b00721b63c04a57e04135a4a9042c4965b4f50c505fe26d34e0e71855ee47
ff05b4:e4892c9a4b6e9393ebdfedcbc2fa07b7c6b480a2915c66f47099e6f2ffe9a1c5
ff05b5:de9d075656763ae7086373eb90126ec240e4e08089b61c3c9a1b025cb6f411c3
ff05b6:52c730094bd1af98ec95105b6d58f09bbf080a8661fef03c5e7e31c1c71aa39e
ff05b7:397808dab0765b2d224831fcd34bfe56a4093f14c48a700727bb31a7ad420cb4
ff05b8:a7c081e1f8d6c80c4f3dae57def94d11ab2d6a6439f98775e010022a90d6d1e6
ff05b9:dabf2e406c3da1fe15166596e9029fadb1c3dff59670d8ac5bfb6345198bc1aa
ff05ba:92a5f515ad35d3a27c490edb135de7044b1e399d608ac1abe883fc82fb4b16be
ff05bb:a797108a05ad9328585fc0cb842fbd824fac6510b8d7eb4ff47991eee58aa924
ff05bc:e0dd6743d6d08e2ab18884ed1e7e46b3d9726fffa9b1866642aebf266fda2654
ff05bd:15ddf98c57e0f46e5c5ee00283bc4af8fe0e8d2c42151630defffa285ea62d09
ff05be:573f5f797482f567edc7901879457bc46c9df0acfd8ce7b1a8fb7e2218fa477b
ff05bf:c261ee3d4bbdc456ffb67868363fed80cb5c9ad7af3f5a5dacbe32becddd88a7
ff05c0:eee6baf50b14bca04202b496737e676f713e7431ffd4fca1309f661481ec520f
ff05c1:c28348740da36cf14ddc49280cf030ab9ce3b0ace093b0e1ba189456f4918b9c
ff05c2:2fa665d9fecb2d5b37af57dac187357e371a6307bd11e6dae635d8c20447ec27
ff05c3:bd1145eac873a03d3623457d9b121e9037607640f7363b4bd74e89871a202540
ff05c4:8b7ed5358484781f4c08376b183b018c957908caac32aa72acd02e51707a58a7
ff05c5:e5cd0dd44e1120c79415c84f5369d79ae04f047e80dc0856351aabc232056ca5
ff05c6:48569c4fabff4e3aa22e0e19613e90da89aa2ee2469b0718695437f5384edc4c
ff05c7:72f104084db7914bd8afe6e347b9257ed4c1d7fc71d3f1e51f3cf47b739b386a
ff05c8:0030c68c53fc05237fcc7ab6017d81febba06315526c57f7e72907c87b982b61
ff05c9:7f4e38b8b22f91daf46ed5856d6e7f1180296fb152c026473c6328519d2ac99a
ff05ca:bb320985266f61c5d182724f15cec428a698ed71262b4e097cb11aed8a41aae6
ff05cb:d2a3d4ed9c05964f4a0984381933c5ab1e93e4a0ba7fcdd60940946d68bd6262
ff05cc:35e3a189177a66860d43453dea17ef74ee6b72477b0e539da1d23d2577b6ebba
ff05cd:4d12db3cc927b260dbf8f27649f0aed05110043033e709344f263930a9eb5631
ff05ce:697854eb0e9a4779e62aca1247f58796cc534d549aafe61d1efb8a969724f458
ff05cf:1212e82c76be77de743aa91c55fdb3f45544d8ceb9cf6496bd0eac7acecae91f
ff05d0:86e87f5ca3aa9638d32173e6dc1de5919fe633cd970329d33f696501c073f5bd
ff05d1:ce15f4cb63b8945d12d556bd566b40a9a4f62abd96cd19654ab826541a47584c
ff05d2:cde09f4f8c8b8339bf505b5a5222219a4bf49e5373ed060a278b5ee54f1f017f
ff05d3:67b7a670e0be073455222463655fb90c0c2f129b0a3505a28d01475aa9a479a4
ff05d4:b9b64892d0ad47192c13f15daccf5ba2041bb39f3041a80faaad6fc6c52a8a50
ff05d5:5953cdfea3bedb37e30de889c3f6d06e000752a305e0e0fc6f544fee248b325a
ff05d6:d945df5d4917aba0c63c25ab54410f6df9bd5d1e1a3843040369981925928f82
ff05d7:f6be748b438846f3f520190836f17527eec709dba71c9b32f81968ecc0254757
ff05d8:10b608e53e0f3f44432a32b906cd753001736ac8bfe90ed3a0847df285e2d977
ff05d9:0eef05bda7842ea85d1d9812495efc561283baa90d1431c579dd61f7ed9269a1
ff05da:386ad965da24812016ed3f011f2112dfd591693dabeb3d0e61b1145f5f9d1217
ff05db:da738a474ee7473c9699ecba8eb5f483ada967988185a05975c4ba0c01b39559
ff05dc:7e687fa866802535c3afc393939376d4bf0fd753d9421719a8aa91a4ff305ad2
ff05dd:8aadf068a1b7c04b3e346f7c97fd9619fff14ecc6c82c2f15594b9732f3f3e72
ff05de:c5eb54eb458e38183c70bf4bd1064d0cf557ea07eaa1cb305968e8a8a50733ed
ff05df:d5d9445eeaa5576081ddf2e6c0904091bbc79ba10915e5215c8a2a7d87915ffd
ff05e0:a3f2a10a366aff774cbb4e6ec4c8a8ef707c03e932b4c46e5078767aacf1ed60
ff05e1:3379233c434610c8eaa9361acbdd24c7d655409c6d680a8c2585ffda27011ee7
ff05e2:fec41e32ca75c295a6240fa639d3abe3bfb5cb131d6690e2331a176bed2e5bd2
ff05e3:d070bf019cfba46c8d3414d6fe8d7d21077f3545c2fe839e3d250f324e37c5ab
ff05e4:4648900b04272628ab7b2d82ddf74cd5b78d77f8652d5bbf2824bb64dd178659
ff05e5:728daf406fda9ecd4d555dc12f27d67d6de44524695464a120669200f20b284b
ff05e6:9271ca7e88ced25ed1d1f8e08afa03b11d1fe12ed1125585ada501243e2cac09
ff05e7:6018f0dffaa4d48f6b363dbd895b43d720691f9658e3d940727fb1499d525005
ff05e8:288b4a9f605b09b999b215850825c81f9b537dbaf23664aca98bf6ba98edc379
ff05e9:b400250ef2b09b30e9aaa3e2c20017b8911bd039df8af54949c60aed5bf697d4
ff05ea:332f9eae3650c77454af14fe1a621a2498fd128773662890a0d12835b3436e23
ff05eb:6ae61943bf4b4fcc8f08ed5044d1c97aa0ad40e1bcfe1bf1b530bd3b151b364d
ff05ec:5a84c94054d340d650a29985ef97bb396352e215aed6c0b33ca7ffdd3bd5d2a2
ff05ed:9a12c392bfe57891a0c545309d4d9fd567e480cb613d6342278b195c79a7931f
ff05ee:3dc08077f76064634d6ede29b438d1287a797d9276da1b7147d1eb80e235eb47
ff05ef:94802f1b0db27426293b12c8775880eff0345e6620079f714a7513e1946579c3
ff05f0:b81d7010d7e495179bb5bb504223ef2eef3056557ee3924533718169f1a670c8
ff05f1:2628d65e94d62e57b6344c31b22920eda316d9be68eef5eacc7362206b7deafa
ff05f2:81a9088ea59fb364c548a6f85559099b6f0405efbf18e5324ec9f457ba00112f
ff05f3:b2fae53e14ccd7ab9212064701ae279c1d8988facb775fa8a008914e663988a8
ff05f4:915ec8dcc237fa932cb0245a996ff3a711550a464214fd7512f225aa608061c8
ff05f5:ab7ef705b0b8db2291c2bc8dc9f69ad8345a3cc543db8cdc49a8b419282dea22
ff05f6:d604f0148a25d93bab577d38705cbaae2c4477de7eb51d86a0f6b26584013d7a
ff05f7:1e89e3d2702d3f1735dce7da99561600534a06454a94874d0780d0443caf4151
ff05f8:e43baad78b78f9eea6903e56f456dec24bd9648c13ae02e2de17a1f84f3d0807
ff05f9:2b6d199f7e35c8c67e0bba829f92991cf31466265e11fa30bd19fc5b6c36151c
ff05fa:9f598af2cee0321800ba49acb9add14545c08ffe4a06efa7a09bc395e36e5c4d
ff05fb:843103fdc2e04b5115c78cc7c47d802abef427216e5bbd0946d105751868c3b5
ff05fc:f0fa7af4e8fd1e397c9cc534eb0de4d6b065d63d62c53be55572465284aa1240
ff05fd:7fae1ef2fe0fc89e24535a7dd19f0c18e3d76cd873e417f4920dcbbbbb958050
ff05fe:0215db7e22d36d0e7535a12691a9ec0dc7f43d83ab580c0709711c1e7a9b55ec
ff05ff:66e795550b16497e7cf4566ec63b56660f28dbd551c357c526fbb0d7620a8112
ff0600:632abafbcdd7e86a19edcb404332a9003a0478d75d58d86aaa776570b1d874e9
ff0601:e53a69193e22faecc833f80631be15e020a04c20bb679fd351f0cb95c0089e50
ff0602:33846b545a49c9be4903c60e01713c1bd4e4ef31ea65cd95d69e62794f30b941
ff0603:ec394da29fd62276cf8614c108dea124f27d459d332fbca9dd2c85b5e3cda5cf
ff0604:afd7a9f6240b11c06d0f6724d44f454e0d5e317d5ccff6b818d57244eed5a199
ff0605:fcac624d61b2933a76e4b83efdbe96a3ea5dadd03d0c9a74d1347e1d230de4de
ff0606:944ace961db316beb694e01c302c46fed40dc0291729e7daf58550c3cb55e791
ff0607:5092ce0e3f70f2fd9561c34623b546f7d333ef1b633c147d1290e28de986a230
ff0608:bef256daf26e9c69bdec1602359798f3caf71821a03e018257c53c65617f3d4a
ff0609:5338ebec8fb2ac60996126d3e76aa34fd0f3318ac78ebb7ac8f6f1361f484b33
ff060a:55a489f60f785bebe042e99a69ac8ec33c9f17374cc4b766f604cf7079ea09ba
ff060b:ad960d6a51af58e1ec09ee05e6df827a7718379cabf0a5529de4b01c122908c0
ff060c:b0f330a31a0c50987e1c3a7bb02c2dda682991d3165b517bd44fba4a6020bd94
ff060d:bf8a69027bcc8d2d42a6e6d25bdd4873f6a34b8f90edf07e86c5d6916da0b933
ff060e:138bdf6e23ac971eb4e626b279dd6a26f057510f1de394293a5eea2860de019b
ff060f:40fe28dc925d1a8a6b8f861863eb57cd30c6776416ab8a99920bac7c925a4174
ff0610:2cc39f6789b967b0282aeaca4548f602a1b274e90d260773e9e7b0f7c0f13432
ff0611:41bdc074eb9531ec81fef08d9ffa16536f61fc59789265e95e89a4982aef3f91
ff0612:3b6fab0ab11c14eef9031969e0adb037c8fcc3366728a6567623d3c26b3632cb
ff0613:d241192cce57d438986723972dd6f18b5a3a3456a708e8f273d147223ab6fa5d
ff0614:493e78eee8cca1f26e6494ed924985af3fa9e6110eaa61c3214e8d73b4047316
ff0615:f9693255933b68159d168aa9a247da1dc66e23c0620338ef7149e48f83b1ae79
ff0616:332b101539fa89ca4e228719fe5287ab6869af31ab21cbf110f5dd3c5994c1c7
ff0617:dfe35c740cf41c0b053e2202ea5afc2f021f70bf90b26bc861fe1d9a0bfc4f1e
ff0618:a7d15e62c78825919fb59bde58efcfb0225b4107dfc60026885420185dc69b63
ff0619:f40da455be136e0db31a116ffd3c3002b1ebbc591558493fe630a9c8c9afad70
ff061a:47fd11ad552ab264d7f272770d3b5590aae145412f4ad6081bdc485298d8e000
ff061b:5b7da1144d260cb10bf295571c093d506fd2379fde8710692b8c04bb981a86d4
ff061c:9924e6fc0e55a9f0ffa998298f30100c1a2b38014ce4b1377d08c42ee4243763
ff061d:02ce16235a88b97d61a7c16ff5146e4f7ba580881adc22650033698b4912c939
ff061e:8faf7d2e2cb4709bb8e0b33666bf75a5dd45b5de480f8ea8d4bfe6bebc17f2ed
ff061f:c32ffd9f46f936d16c3673990959434b9ad60aafbb9e7cf33654f144cc1ba143
ff0620:fc30420d68c17c839f3b946ebdb101bf72c64c9e96658c1f3e357e6ad8aacae2
ff0621:16f6798651d5edb6eec6f952ce0879f8f42cbe8537b33409a79ca49cdbbcff99
ff0622:6f7c6de02919dff6f68859e6fb57a02151bbef7ecfccff9a598130496b5a7539
ff0623:3d9316114671635da0e9f8ad6f1d8f0b12532c97a5af0719f849fefc82b91502
ff0624:143613dbecc6542100b246bf51952364cf7023c656f7067bb66d2d347dfb17c6
ff0625:6a0b7e50404712521760a30bf44270eeac8a602fe97ac36eaea93a72fb3ea379
ff0626:63dbe67556db017a41a12e60b912ce59da5445ff68203ca91b94a4e2a45541b1
ff0627:668fbb257435cf6dc01339af0b272ad15cf4676776a2861cdaf7b4b598bff169
ff0628:f07274d7fd0f2cc71bebbab0ae38c78a355e440a5cb71180365e38dd6d5483c3
ff0629:580ff2bbcb44d874025cedac187332e9ff9ffe5175bdf9d43bf1c52ec8d67b13
ff062a:9416c71fa3755cb6e7cdbba039f630604d0171934f97824e8f3ead4b2a8a5720
ff062b:b9af33fa426f2c8b1983856a5f91fc0d28ec930d1419888fc30df5fb4de7615f
ff062c:1221aab60379e9fe79909aa108dc1c2d3fc312f671cb4bcde01c4e67d7e7c08c
ff062d:5a0268935cc510b44bfdfe3d4c2accde487ddc091319a7858948e911ab5e44ca
ff062e:34ebde3775fc63b6e80f0e47eb0a2e268f7fe4eff512dd41118d8405027475fe
ff062f:95e0f89a8e0e12e3e41d6d5aab4472d7321c2ebcd9290e78d61697cdf5d43d66
ff0630:e3e2a39309632243fa0aefbfc17d1809ac99a08b081a2a23857e8f95df0ef0b8
ff0631:39fb9a70f8d73502c140d61cee2d63f5c120af987f5bdc07431d86effca67bd1
ff0632:c8b068c2baad86629f5e86290106080cdff8e6fcdaa8c41e463a2ac4ae1c4435
ff0633:9918da34e4a40b33c6965f0772799f83bca369fa42c6b8862deaafc64abe3d09
ff0634:c47ee2472378948f335ebd80bbfd8f899d156263eec823b87dda941c6a34b771
ff0635:6b653bcd7382fe58f746f2fa3b050e8cf6af355968e1a81753e9a2244460cb03
ff0636:4d27ef6357bc929783575c0c8c9340b67fbefc045fdc263b8c88362e6d3adb6f
ff0637:7bb647a62aeeac88bf257aa522d01ffea395e0ab45c73f93f65654ec38f25a06
ff0638:c90f26f0fb1b4018b22227519b5ca2b53e2ca5b3be5cf18efe1bef47380c5383
ff0639:a4adfc2917bb1451d312371d441acdb686107fbc0b3156d5570e99e1121974fa
ff063a:f0f573763c616f762aa6ab927cbde789fa8ef4e69af8a27ec63c62eef329eca1
ff063b:2c171064dbfa280a1f294f72e2a1fc24c86111b23723db9375d3004b27e7b33b
ff063c:d92e93252eabca950870b94331990963a2dd5db96d833c82b08e41afd1719178
ff063d:a4bcda32d49cdf05f0cdd085e73c3a2e67880bd48579fed4df5940df76a076d7
ff063e:e7527e30d473aec3b162afdc47095449d2dd5494ce862e2fe4f436c081262f64
ff063f:d859828e4e8c35ecc38e415e1d0cffd4a9dfc116205401d1298fc13347dc0187
ff0640:3647aac2b282bc941fe7a642e3dcb99cfc5b3c6dce944a1e96f8028e89b7b090
ff0641:7c4e90207b2b7caec080426cc469908cb27b925ee3b1c999c22b8568812fda8c
ff0642:f9a17a00e5c294ba9614a715819af57f3fd48cc413453fbb8a5fc7e97964e2bc
ff0643:cc1b9f9e4370fb68141d28a115eaa863f8eadb7a04e2bd23b3c62f9d9f17c263
ff0644:22fd54f933b17f458942c345e3ae625e405ce40b191b316b887ca3d02ccac3b1
ff0645:bfbc39e9fa2b84c9a92337e2344ee2381d8d3d3ae8ea75ef4e48e5807ed80c69
ff0646:7f3ee6366236ede6c1f7c21c443c644d32153edaa9357c3a6da879cdf2a6b0b6
ff0647:ffe930442dfeb69ce29a908b6a639b370bd6ba6075f931ab83561d938b453a21
ff0648:5d1bc399274e649e1c72697de91a54ad725088c5221cb61e17ee9c290bc42a92
ff0649:ecbd2002fb15d690eb29cca7371d97f84fae7f1ff67bd039323badaf5cad9148
ff064a:6cc95d21d4c7ba39736e4e703e4260b7efb6dccd91431ed5c43d7e0986b39554
ff064b:68255d5ea52d2ca9a0b1f8eff8f446cecc95a80a5d880db681f1630c0b4b214d
ff064c:4cf773f955fdb7a97db1250f2fd7ba36075a96166bb5cc417b5c021d0f70adf2
ff064d:ad7f57aa3fc5eaf4310224a4750a97cd879de1989d4b86ab08b7a28373bcb489
ff064e:654bf73b2639091fa18f296755b704959f52f67fdf7a65aaf1c315441201a09d
ff064f:169cbf0547f3dfc4e63e4af9e0255a76037778ff5b8f4a536abdff3a91dfc3c5
ff0650:2c4ad64b4e862d7d46424d9fa13ea9a974a62f7c4b608ae1a871424cc9a6873d
ff0651:00482341b104a0de6e0f1d508db84cb514f7494fe04982133a5c750136c55dc8
ff0652:ed3f7fe938d953af0be09918d7e59ea20b662afc4625187ca24463d65520a23f
ff0653:fdc1e2574f397d8bb0bc436eb02f9cc07eeb08bd90383a9c32173c889bdd8e96
ff0654:da00b546ba7be22b146b74bc23daca3960464a84779b0116583bfd8b791d41fd
ff0655:8d53e2a477a52c38d07baffdfb7179592a344dcb8ecb75e1af8963c9a2fe9c83
ff0656:82a58a9e489606c301562fc59da2b1366038e33c3e73516fae84b8f17fa5e4f5
ff0657:2529ba3064ca9a4cbde2e444a1c87d046f6915a1efe3414df5bdb6a77dc620a7
ff0658:379de2aa6ef4b17e1e6c0d9626531f792e6595917fb2d28a9e75eab9ece9e743
ff0659:87e01cc4dd0c9d92a3dbd49092ff13f9cd387445cdc57e5b984e1b7721b5b029
ff065a:aff8f4775b215cc5f354b87b000def768b18da8f8f312d3d7fe01c79ec8820a5
ff065b:b78d8eb347f8a6777ebf9fd23b83800abc88cdb3cf1b40706b11b05f1fa06fbc
ff065c:7f4325cc24107a39441552f27fdc34185802482e164d1794aa415ef1e4206ba7
ff065d:c619f4e6f7b1baa7a6c6f244092a3f82e46a6d67bee26337fbaf02546f33133f
ff065e:d53bf4968a7db3c8c4e3366f2c7f76ad61b7041dfefc64c1902c499a6ffff241
ff065f:8534345e71f5450b6bd2758cef8495547008a6e302ac8dac625361cb24dc6bd5
ff0660:f16c99cde19ed1ace8b4fbc700e05e7eff2116fd6a22427766b251c6e8bb3ce7
ff0661:8fc89b7368a29129735677440476908711da8f3f04c0ab6a61d6de9d4eb4d1c2
ff0662:7cd6cdd25eee2512aaf1419afd44c146c43aa1093d5a60d4ed39efbdda815ad4
ff0663:b480e11a6bd0c2bc538b1c7db1c63b40694e5dedd93752d082d9fd422fcb3fbd
ff0664:826ebd90e946c25d3df05abfb911ac0a426c7a9a063b7224464710bec5a58ce1
ff0665:6fe24fbffbbffbdc3be69a472dbf75ef30cacf8aea319f3893654c91bab91143
ff0666:05dc9edc0fddfa975a1432ef806ec780078b5362ad45af76db15c907630db25d
ff0667:662871c80f4e0fd219ea69aafc4d28ad7b41e9381560bee787848d4eef1cbf24
ff0668:02f40238ba372e9df51d7540e04edfedab5439323f9a02df5b38c074ca7d406e
ff0669:34cdc67d88d25217adc8a25348e114cbec63148391cfa475d382874695202d2c
ff066a:95f6b9230f27fb5fc0cb29443dbe7300168b5992c7558f3f63d4352f32b8c9cb
ff066b:38d530fb170053617e47aa6ceff21c2db43c9d96741af1584566072091474bb3
ff066c:943bc406b0b45acf88413045227265703f1ac8b21d6fbc2b8cbde59d7ce51b81
ff066d:b5528f4a43957e1abbe08c4ebf2d8acf4c2c1914d6354117492c8c3fe033fd97
ff066e:1ca57ef159812bfbe2d8106f6152e51ddd0a5a4c9489cd097595b797cb37843e
ff066f:7bad1ebde38c5226b5ce118e386775fafbc4c8a545598d965cd01e97491def8f
ff0670:afed062e87df98182ad9bef7eb13c0e2f2b6698ab4e3f33932a10e286e024e9d
ff0671:65248fa866c854908d0db045f88cdabc9452553b982aece6b0d845866b426b7f
ff0672:5534127f056498b4cf1c967365b1dc2d44f33109abcfa6454f25bee4f2b65481
ff0673:7a3839d4b8790b197440c94da687dceb1a5ac07d936f81acf40b163364b0a951
ff0674:aaa627eedac466dbc4c7750c87d999588ab4b03e74b9bfdcda2902dd36dae0f8
ff0675:25026febe5324eeaca89376b13edb96991594112c311120d579364e3cc0442f4
ff0676:771cae51fdb06185f011b768f6469918854e9efc5992d626399f8aef3fc10db3
ff0677:2127dbb280a2b296039d17e2e642eb9346c33990ab4298a664adca002ff67ffd
ff0678:fa41f99d084e19438144d4fa7457c89aba1bba150bfb9dc4bf9d4d73e6623c6f
ff0679:eba6880a6d960a2692a05aa539ef1c8ec03b3c455308dee5a0f6a4dc050edea3
ff067a:8ff94f390ef3d4b472c53399e25d8ca74636f68264f456ff5f111cd8cb9c0fd8
ff067b:f5ca53d8790d2ac5e1275d2e10dd914a924f2004951144fb8c73556163a2652e
ff067c:6564bf50f3520375b11f2a5bd432bb44e810adc7eb2c4ad22f9cbe0c32b46162
ff067d:86e5811af6678c23fe7133cc92a27e93cfb85682be0c2954575e7a4d06285598
ff067e:7cfb624140efd55d44a324d10721caf48dc64755db6d11920f8d2b512f7eb70f
ff067f:aedcc1dbcb44d96f692bd451d76a3229839151d5be82fe8d0d1b23030f48fb19
ff0680:ba0df2d121a739e0002aa19b5b2400f4204a324f28669356ceb0b1b2dadf8b86
ff0681:b95d0b51aab7504d0f8780173b8c395dd718371ba61ade30c11b1b77b33ec01b
ff0682:fdb76e78a450c0f3af093d5186c3b28a1280567a0ec531ca5977ff4e616b35e3
ff0683:1d75a0b37b4ae11e883c97d3ff0dc5d84d93fe129c12dd78086c4a78daf3f709
ff0684:49c1f25a88b5b15a80c1a2da11589111c5ad8e222104fdc49022fd6aef1cf54d
ff0685:9e561a4b486076c219f3c95387bf11670d72f6c4f0dcd9bbb47f59f5c142ef88
ff0686:290e698939a24f7b63ab14d0490de92bebef6c1c2d3be717f3775b71c1ab626d
ff0687:d43b3fbc2e6715b33d3d7037200fa9d4181f97492c44dbeba8fbae9680d64cd0
ff0688:07f55a105e886d191fbd2253283e77b1fc1ccdcc9f26a3e6c7e69706a7593fef
ff0689:cf8f3e3a993c9d020068b7ab200ac94200748731822fd5b32767226a2ee4efa5
ff068a:578af4ded0853f4e5998db4aeaf9cbea8d945f60b620a38d1a3c13b2bc7ba8e1
ff068b:da1f7cbf322e55cc082276f8519147dfa1e80cbaf7d5799ff771358832ed1712
ff068c:366dd61ece49ef68a7e0705915ece7ee7baa3c5d71b9363cd487e0fe0242a634
ff068d:f4e26beb0279228d96d47b05df744ae6ce6aad888a3b757d249eb3d22d27f4c6
ff068e:3f63bb2814be174ec8b6439cf08d6d56f0b7c405883a5648a334424d6b3ec558
ff068f:23d5efbfb41ce7b1f30bab8a8f64af85edbb5d7a49c08d616de4c47cadb03597
ff0690:41efef46fd0e434b644bb47e6e21182a8def59b1e6e1f2952587fa28bf10a4a2
ff0691:57d61f0944948124e9b7685c7e2c9b4344e75da9588328ecdf936ac8e80b438e
ff0692:f1728dcaf61a28069eea0fa1b482dd61a463f75255dd700cf60607e75e93c9a9
ff0693:0da999df66fd21caff5e1376abad37b4fd2c8aa69b25a3f60794e6f3aa47d98b
ff0694:0b9df26ff87df92ec265661eec82d09f8a7531006f3cda4d6f7288961b23b045
ff0695:604bdd260a28edd256e9daa70c05cd18ac3cec827f842590d45ea42bddc61e42
ff0696:c05f6e75226a6ffdf4a07a6d7473d3c51e66a57fe81138815539157dd57c5a59
ff0697:2858d518d0774088cfe7bd5e52aafd15c450b63c667c9f575eb22c084fc2318c
ff0698:2ae0626f9a43edb2b0a22d410eb06c482ef982563a717a247287c504d79bf980
ff0699:fe3cbed838d30bab900184c1f21a4b27d3211cb5c9257d7e985c2ae43ac6a89f
ff069a:873f0ba80e3ac222656dfd04158cc15c2927d42d5d05f01dee4a47eb43a916df
ff069b:4102bb08b7ea19e567eb6710384c540afdad993af0d9dfbf91ca6273755b8ba0
ff069c:fd917b0d094faa4db1bbaf9ed7ac55be5162d971c227b34e7085ca537a4a4b47
ff069d:8c54c334b66ba4e426772af4a3f9136c19a1aec729fdb28c535c07a5a4ef22e0
ff069e:6542d176bed50f193c0ce297ae44ecd8a0a86bec2ede682769344059b4e78530
ff069f:7a1a24285e25e94df27ce8b344b1bb6b32f0254ff0d7b5ab6e856ae90cfde55c
ff06a0:50f168461d8abf3d04e54becd009645d0b71c49fdf561e0d8d43ad9005c7f8c4
ff06a1:6997a28584ad0ac6619136e2bc1fa9c631ca3024b8284294e26fce336be541c3
ff06a2:26e1e17b579f51de03204521b6d67323c97b0f351e9923c5aa8e7f333f9ab48e
ff06a3:b8b18babacb6a94eabe6928c6bacf4f6a2d84235d7f866486b5f784473be708c
ff06a4:c1f78dff4b13d64cb109eeb2adfc4b16400cf58e8c085fa95472ca51655904dc
ff06a5:898c44bee78b1634c8d580700a38146b9f5809eb30703422bcb35f404e6a10ec
ff06a6:2925f99b9f776f841d0b4c09a07f0a36c107f0937611e83e007a712e4b7ec735
ff06a7:3dd69c5be170f943f804d1d31fe8f916c0c0226cddd7aea9aa9a0cdfd3474361
ff06a8:f6f8bcd413c9733166e85843b468dd36e727152d9a37b15129c0e7648ecee639
ff06a9:2fe4dae370fcf2b58f0c75f2abc49414b881f554ecf21485eae73feaa17b1dcd
ff06aa:6557a37403091987483d6789ed9ce4549312674b91f57572397aa76806f009d5
ff06ab:38cbb87231f062a82d7ed2ef73fd4e4b84352ea7dd7f15686de3a9414b7ae029
ff06ac:73360680f0c0de2c542eb3dab2b30764d5451606501953c76d51a2f6ebd1c29b
ff06ad:dfc6ee42e6a7b339df178e566efb5482aa1a460c586a32d67c9ab053af2be657
ff06ae:caab391e482ee136be74e3fad9e3a1ac589ebe060b95508594876293ef87e7ce
ff06af:4de5fb201dad1c9ccea68648c2a9a03e53d5f39b5959d0608e707326f0c6432a
ff06b0:f709c820518d6c38595cef8355dbe02d24163b9f843652ba2c31230fc5806220
ff06b1:97afe7c35378c386837676a134d7a1d472b72ef091f224f9986c8256a6d75296
ff06b2:cdacf412e2921c342b1943676433e60488e4bd39f193a9c22c12aa11b6796597
ff06b3:fc2811137dc86c7987d5665e22ac4a2741ce54b623dc58e80ce90ef8626f67fc
ff06b4:405b1e8b6cbddf1605c82d30af52f02d8938873674eca18a92acbace22610bde
ff06b5:d454487fbe3b2cbc10c3023e73aee27f3e3640726ce7bb03bb4244b50cb2f4c4
ff06b6:2335d5edfa507eb56b7dac00f434d55b9565a6f968e4cd3ac01bac2317a10b16
ff06b7:40d44fa09a260e8fcd527293aa965f247b31e2104fa51b36d263b0479fb828f2
ff06b8:d7a8a9947c31806c1b4625f82fcbcca7cc2090e58db215b8e4d88ba9c60d3166
ff06b9:ed5bf864daa3218402b7e96e8b1fdc96cab3f548f5da55ff41bf18683930ecbc
ff06ba:1cf341ae35341ac3ae1dc68d5b10dc0c9dc1307656f75fd92ca2c68489d52e9a
ff06bb:5a86cb297e37cff1db01fea8e14fe4c5e054f8b228e976e4a782e3aea723fc1b
ff06bc:b9d53f235c5fa8c92eb31dcfcadf4959b34a32af36aca1ea10f07d6551c398a5
ff06bd:35f8cc89610508bc16bd332da543964698c72d67895feb4e068bea5e06686457
ff06be:bf64c06d1d48d977a0bc2dfc917e8e0d6342bd11590471636d7a0806cc8df003
ff06bf:d34a5b981a85ca075db62cbac415ef659d95339040ca476868625d4aa23a9849
ff06c0:fe79d9491b40bde3f32ffcb652823c85e478ac5ce63a2027d39955ba7f6ac23b
ff06c1:347df1f3872d14eed14db387e41beebd39b5cf0b468ec08806d06108d564f463
ff06c2:1d7b3634de39ed80a3c483ddd5ab23ca0bc6bac9b2aba3db7aa332bc0fcb2a55
ff06c3:9b78649dbd76cb5e1bbb4386342e452fc87c99bc711905e5f429126e58006fb6
ff06c4:3717264d6c5d049b1ad59f4b5761efc94abc3254285d1e68109108405086c4f2
ff06c5:cacb3945a2d3097a5efc54fbd2e0ee2e1fbea711dad665bc7f952da92ac8d657
ff06c6:e7db0014494048f226a673c28b725e8ddb9ccd4867a8552d7ae85c2523bd2655
ff06c7:75585a11d7551d4ec507b8aa9ec06c06c47e40b7a5cedd183b3c342ec7eb7a34
ff06c8:0032295b0b9cb38a775af5ec01adbd2d3989200d8b7f5c7333cd1c061f882e32
ff06c9:4d0f5da23b099209b048e1871b4bb1c4b4e812e3fa0249bb8d19e00ffa9e91bc
ff06ca:bd3816423553ed993fa44a02f5562470c0cfb0d3b00532e3526a4a3aec87522f
ff06cb:2c99b917b7a068578f7efb4fb8e60b9cb5a0e73bf300e0e1dc112e5654c5ae52
ff06cc:3d3f4b440f933ffd269565eda9e20e8df863c9cbe3651d3b476c5b4f4af5ce28
ff06cd:fd39ffc48f148354262162a2f55dd46dc2564cfc1499309ad53f09c10981dcca
ff06ce:fbb7926a451badf516be518614a77e6e325e29819908796d807f59320f918ee2
ff06cf:cfdd061fcd4cff3bb9e133264ca7fde45ca49b70cfaa977ae0dc422b4330a8c1
ff06d0:2ec9a5ba68b60f81e5f8662f7645743cce1edce06af686c775431f7bbb69abd4
ff06d1:d904a27fd2d271dcfe40a1f471033ce48a4b5e1484753da66f7166d6ebdc06e6
ff06d2:6685871384605253c264f8d380a8d1dd50a6ca192788ff2d560cafe541f807b8
ff06d3:378cf8738654c8a8544812b1ff2632348225553da80225692d0491c4a1eeafb9
ff06d4:5ff9f5a1c0ed7401e1c529f6d50c4abb00b17b593358bd2d61dc0dd887ddd92f
ff06d5:7a38f708a35a31e42e1cf3220f9a2d273e7666354618b2464657d43d8e77adc2
ff06d6:9d1bc5d2dd75bf8b64f35e7f919e2546c225be888c1a8cbe82c0e9579234a7ed
ff06d7:33f9731be910a66dc6acd07d9d9ca212ee8d0a9a5c78c8bf3e89bb74df8fb936
ff06d8:724247794951c93f3e41711617e95ce143263e3196c345a1da78f6639749ec03
ff06d9:511c1c41cb7eb2a10078c32c82f17925ba786de46c633921d038e7409e15a5ea
ff06da:bbd27139c5302c63d903f570f173ad4dc06c974b9ebe292c90ffccab5d6fa54e
ff06db:7a3ae4f12920d5a8129be1183fbec4370ef10b8b3ad41eae4a58d5385aa94d33
ff06dc:be23414a42e74886e7c72a861ba2ddda0175ed829223d894c5d272651fc0c189
ff06dd:89aade767b7ba43f8dde8e9e74a2fcbbea40d57155f7e1f2259c88835601faed
ff06de:9e7e310303eda686fcc5f55f7506895b15ff05c780eeeadeab9d016db672f3ba
ff06df:57e0b33504dbaf6f29a095cb8a297a4abec121ce11640efafc17594098f6caa9
ff06e0:82fbe865da22d1f25adf94bbd809d3f516125849e792db7bb18452304c2ecc43
ff06e1:853b06c42e26160305cc3dd5b1f7f7dc6bac5602c0f444f08d45a7dee1f47cf8
ff06e2:624fd02328d23289573eba7d1845258d70e15bc281e7da38dce06a5712b254a1
ff06e3:322c1afdcc9827ac4d234780082a9862034941998aff67e6d77bc4c560db25b4
ff06e4:647987d98d52645da4d3de3b80771a0ce02b9b9285e6e86999882170744ec9aa
ff06e5:7f1ad73878e0ea7cfd705675c4dda688cb25e122f6c8564fddfc14bdbf041837
ff06e6:dd6c44b39401b053dbe61120748bbb0f6056007665c168e5c286750edc8df129
ff06e7:937ef8f12276b3c7a3f58e345d09a6eff01f862f8d2794441cd84d511825fa0c
ff06e8:420332ef876ebe78f2af5d28aaacde24aad0c10f8ffaac469efd7bd941929568
ff06e9:5355c4f8c6cc330b0d813d6194cf206895ee6f3977ac0c99e509260488e6d5c8
ff06ea:a7dedf5a842167dd12fdaa0f2080e73295b8b8bea71b2094ea0950945a482fc1
ff06eb:fb327fe14ab3fec5c96d9169a8b536382b97b1b325543c3dcd8a10f8c431e103
ff06ec:2db842f824321277291266b230abc31de13c1d4b852d6c21c9b1007d5ac20681
ff06ed:aac8b9394c3bb0376622444235343371c59e951ff85a151b3fe19c288076e2b5
ff06ee:9ec6ca44d6adb5daefefc9d773787e3bb8e1243f5455341b8438a6776869333b
ff06ef:2426c77cfa12ebcdb6b013225496c0e7aad66d63597ae5ef9a0beb3830c23ec2
ff06f0:2126c130f1d576fb70cf3b8e8c0ea2fee8cfe98d721304eaaa6d898e721029ce
ff06f1:5655eaaf7133936558cadde8f3447615f759c9c63bee949d4dc3cd7fb71fcbed
ff06f2:c3d06e5271233ed46a538c150fdcdcd73f88aecef624b8d16f981c13742e924d
ff06f3:c0a9fb425d0edebc72bc6c47ad3d3a2b68245ed1d59a5883bf19ce9f8c4ded1f
ff06f4:048e39bbb6b15ef83525f163192cea0df21d3ffabafab7c63909fb1553ee4966
ff06f5:b9ef51a5f69a974f8d290b0a75fb253b7339053002aecb6516a270ea88aef4ed
ff06f6:15448c743b75dcc18d782728037226b6f339ac288c1b8fecba5892556e5879ee
ff06f7:3c07d7efc8d458f668c10d4f06f90503ccd25d59e2b3f1d58b32884d9e4e3809
ff06f8:9c53902f9501f6d89766999dbe2ad1a1436420b652535cdc2dc51ccfe2ffee68
ff06f9:27417a09fa7410b9198a1b0645cdfec28079ef5e8143af2bdb697731045027ce
ff06fa:3485c3dfe98c5d5428653479bb90627580ee892890a62da0d9abce3a2002e8e4
ff06fb:f76e3339a6773dc5922da154628c8d22b5c915edcb15270db8fb3d8d24959e98
ff06fc:e0ee4b421d9059224f0cd3ad7bc9050b1ded78718a4ad26d8de3fb40210f1fa1
ff06fd:b8c5418c43f29d28ccee6cc2795cea84d0b22949b162597666f7893126c3ccf5
ff06fe:bb32b9044163d739e82233aebc7ef3a23565b748242efe0973098748287d9e76
ff06ff:67a9f71a282c4ad07586ca297b914926c2e1d331c5f64a46afbd7d6378d89868
ff0700:ad4f4efedfe81378fd216e168ee1eb6972b9ceb796303e94bf76c5af6350bda3
ff0701:d786d22a7bd61d06a68586376dc1226063592f4d864ac4e7bdae40afb62238dd
ff0702:c905cafded19bab5742f3a32f6c3cdefa4e49564a348ea84be2d033610816ec6
ff0703:c5ac82d56f3dabbc7d2790ffbd4cd6be07572ce47ade456db30fc48e60352cfd
ff0704:fbbf50730e837a7436085c92483550fd65d85e0e4dff121f77cf0f3b7c40bd4c
ff0705:4959306bae8c548d319d1855c34493f7ad00b9baf824bdfd96ff2c3c32bdaeea
ff0706:e46fb2a75097a345d4246dcf44a10daa71d9fd0ebfab61ba67e6db84ee5b6cab
ff0707:3f6f57f1fe25b3d6f088f17704f7e376ae3a91151dcd8e1917cb3a41785b5f0d
ff0708:b97e1037e4cd5c069271600afd1ff345eeae1bc2c023a5fba8b163260fca5dab
ff0709:1dffc2ad5b423dcc715dfe54aa117f2525974d9571fea82819232807f4add4ee
ff070a:193144f431e0fddb740717d4de926a571133884b4360d30e272913cbe660ce41
ff070b:a115ec0d73c2e8abb1883134fa2df0d985e741881604a4082907d705e2407c72
ff070c:12d4537a7547ff63c36923622a281affe9481120db781776aaf981a1f9b668d8
ff070d:c04c30e40dd7e96982f8606ebef35548e5c6f4f792a52a5178cf24a0e9fd7396
ff070e:e52725dbc9bb6037367e75474c2d135c60f643002a3c0e84589e379d7cd8e9dd
ff070f:018f6b363b543a4399448a1ebab9250ebfd0720016b0b411fc86f7e7366c6782
ff0710:abdce06d6612f3d88765cd579f684f8f2825b24c483121d4af0a6db38fdcaf44
ff0711:d1f35afda0483b9478b4dabb819f9887e8a7fbf6be1b38b38ced919567c3e72e
ff0712:52eacd1404af447bc93247677d3be85c6a36ff2114be8e95bc12e94c0470a0df
ff0713:d0e9157456a6e76d99cbd9458447cc32214346a5b6c55854871a005ee6e500f8
ff0714:193d60082f32e695f00af8e03b37987aa908ace8b78dd0dea7e0022b825d257b
ff0715:af8ed16d3e437437cabd63b0d26958f0220d89dc9c70e1566ec2869a54b1233d
ff0716:c4baadaf730efc93441cf184d60951270315b065dd4200d8fa15d349b19469dc
ff0717:e98682c76b048510ade4e70eddb460102ebca3be4b8a11f25716756089b1c813
ff0718:1ba590b9ab9491660ed7479f953997caa71c3db251fa1d2af1f7ef8b52e36f9f
ff0719:b38bfdebceab7ad72fa656806d7bc98b8d59bf116398e596e13c9b66ee070400
ff071a:0a5782e042bae8a33f21c6e7df8f6a453442ac0ace93180c0397f8050caf08c1
ff071b:d056a5692f2a76daa0a5ae869e1799149d530142aa8b5e6feadb21c5b80e1169
ff071c:435cc6603e9cf50e76e0ed0341ab80bc21538e3b8af68324da5aa177ee489537
ff071d:485475c78cfcfc8e7d1bf4dff9a6c48a24e487a0fa0016e5c23676998c30dacf
ff071e:12ea73bcc09bdb4951131dc7edcd2a49d2f9031454ba71df139f3070337b1e9c
ff071f:14f74902b898d199989d3a33792809dabb350d44cf03c9c498048b486e443804
ff0720:002e86394b246c191c4f9304f821b11033d7e0a75e81cf39f266ae4768998271
ff0721:90333450a3af1f42db5954f84914b1862771eab466ce52fdd19eaac3594edd3b
ff0722:9b73f44682921a78b0b0961f7b031baa8ec5d061f54def326558c04f1ce3b356
ff0723:581460d695b3807f8711f2778dc22ebdd3b18ddd320ddfcd28e3619cb280b0c4
ff0724:2f904310ac359f05b2e0087b2651e02437c27da57cffc925151f5f3679caa516
ff0725:cde6fdc1368df71bf156b86b00314a5607578f37612dfb3f974b05863be7c91e
ff0726:5508453c2069cce80dcdd140726d097deb08cee0c9b3567863d2b516a235d666
ff0727:551aa9ce3edfd13a912b3dc9513f4baa623085dc22a11522a16b77b474f1bb37
ff0728:79a4e8044a12c9c25caa53032cf49b1ac7ceeaf1f8b0ad93b19a5b6d735117d9
ff0729:1f1b69bf37d3e228b3a0f4e89ec47831c98f38a845391b614fed5908705cc5dd
ff072a:265fbbf5ea8612b964bdd232002040f5e5320fc358359318e216668deddc44ca
ff072b:39118a120e7d36886ae632f6166b259ea9575ef1d09a4cbec0e17d836c30db05
ff072c:736d5aa3dac34c7a7988cee0debf4f168e3e066217e5a838ea725808897f7332
ff072d:37d49d96d32d9bf868433ebcbca72001b17ef59af659ff1aaf316ea20c84a8ff
ff072e:54126bb984b3e3635b91197633ecb4a898af2ff0781a7f33e9297365df6b3b0c
ff072f:ce7fcbebacdd059e410dd7628b2326d7391960b7136cc00134b935cfe8b59771
ff0730:f6138950defb71d2cb1456401e1be00da15a0d3b3f39abb9555dbc7c3ec5c2e3
ff0731:b8b25b65955e75e3e2983cb27b431c97bfe924173b7f77673ad59f7c523eaacf
ff0732:b1e42ecaecfc4b29408eba5983dbf3922d39421c43b6a61655b03f9aebfe4a21
ff0733:cffd65450dd92a16792978a05ff239b2db9eb7f48e9dfcda2fc377184f2bba66
ff0734:9d4f0abd0a402c7074fa19eff27c96fed306dc280a0ef5ef864373c1697a01e8
ff0735:1b52edb396ea4e3cc986a7dd3e107ed2a070205a24a4a9849a18820900c8baf1
ff0736:960afd451f7b5416708cdb161a471eef43939e5240e9f4218f0a59b866946b97
ff0737:01af2324d098098f5e0cdf6faabada430b21cce777f47eacb26248b2fda3e531
ff0738:ededd0053cb844592e673ef2a081c15b38ee3ecbeb5856c9a4fe9b7169faffe7
ff0739:6523c34f1e879add7603cb2048a898a5e2f0c6c4b512c0d22782b85d43ae3371
ff073a:b2fda13f819007e924a5ff453fb4a450c2d3451fdb432ced4abd34532d4477c2
ff073b:4436a54d37bf9934b2ff7aaf235b77d95baa0839ba7e5ffe9640efc6655860cf
ff073c:5ae7385644a83ed2e18c66ecb80993ea17941cce26d1ed6285df83cb35ba24ba
ff073d:efc65cadbb59adb6efe84da22311b35624b71b3b1ea0da8b6655174ec8978646
ff073e:9a6fc4ab4db1ea6f6663507edc1d008f091ae88fab6f3ae56a84a4090529ef58
ff073f:c6e96a1745707099f02279472fa28a99bae447d77511e19e86baf3047651c1eb
ff0740:02609e88979fc6862ea1571f3bc6df6c70f2fe9277473e43fe04c3597c43431d
ff0741:edbcdd01698d83eafa1e3d38f017b3ad96b2d8d88e746c58011cee0ef106939c
ff0742:f5d12415a12c07fde93bd6f9e4e4588e03d20596e4f8a5e9d213a83364bcee71
ff0743:f0104ff17274608f1a18a1e1eabf8e68a51f500a87e2efa22ecb622763fef4cf
ff0744:fb128864dac56f3ab93c371692300dca345c04ffe5a7f6eb24fe6e449b348950
ff0745:0d99048511c90e16631a97fa766f28adeedc1318624e3754b24fd60fd5a4bc4d
ff0746:6a48e734ac6f067140c928adbbcc4492469d416de2d3c9a7a197d62370eac0e2
ff0747:1744d73134f95ce916adebee6f75742c47936868b64d2a0c162ef132900f0ee4
ff0748:fd8e0c8cccdbbae4c1f07c248d11febbb0fb3da0cd0d894a8a80d804a8d39a7d
ff0749:b274febe6ebc71866c339f018ad933e7cd6805b43bfde6d218dc21147169d76b
ff074a:39b6e3b388f749521df2b354182eb4cd87d4bf36439bfaf0202e5596cfc2caa4
ff074b:bfb08828eb69b99ee7cebdd687c8e883a1fe07d3f998347f92ee9356414ad002
ff074c:fb13890c7ab14ff7b94b2714503e31123bfdd340fc4d979743166e0469b47a88
ff074d:b72450abf5047a8af63ec9d87e331484850b1849a2550a82a86db6b41ed38760
ff074e:1ba02ff4a2562bbe6b799563990c88cc50e1182395719a4eaa803976e2f50860
ff074f:1c8c70b263cb13a9e6ee3f097a9673194cc9d686bc14a72c8cdc705f2c0e68a7
ff0750:57a44d4a69023d95beb89a61a426579f453bc146f2a998987f3c7216e78a4b9d
ff0751:c7aa7bdb14dd5ee2f9e6ec2367b64d500de432e7bc51e9a8e4e9791b828cf65e
ff0752:0152f86354fca9525b280c233f7da6cf8b5f2373c42644723226ae67238db190
ff0753:79aadfb93f2c467a37edc83b5dd55a200ea9c32d3dfb6fae2017a2c7e3306dcf
ff0754:10b3103d2f490d2bf2e95eccfae7d6466e089923486196e49431c88ff361d7d7
ff0755:3c1b0beff052ec90997a72352e7d3daaf90746b9a3c4d8987a5bbb9d0370e4b0
ff0756:4be6ba403d6ecfb5e73820f5ca1948253205db186e396d779ac6b41bc8a826b4
ff0757:a79831d06b05530a5533526ead1ef6e0d7ffa2bc52d59eefb41b950aecc31cdb
ff0758:514a14c828b3ab160dd9d11861bbebe5eefa2a6ca0ab86003cd1a080aa36a9d4
ff0759:020eec98a3c1ed2d5be21193349acb9751de071d6b452a489a6a867ce9b633e9
ff075a:60b846638922190de52c1ab044fd2fa88a9d6df3989831c00c84296b8db7a5ee
ff075b:d78be04cdbe328d5493489067b8df1c57e65ea74d8888f08c711e815a6a11a14
ff075c:1a2c75fd096e0499e9ff6ac74e526f61eaae3edfc8c2ea4436fee0c24d8b7d0e
ff075d:3cc2c132fc23b5ac675f89f81974105208d1eaa3fb61b40615fea2a6868e7df9
ff075e:24d072dea5ef54fd6ab3afb5f27ba337727de7128d009e07ee6fd3ff19f2d89b
ff075f:41c29f80b918ef9605cddcebdbdb2683c310c5cf0aa7d8ebf6788393501e90b9
ff0760:e95ef2c74714c4f557b76ef2cfebc3779f5011cdf572a2316d43357ccbf34896
ff0761:3dc272bdee4e4604d498732c28c026963e3cb21df198a29db9428578b2447da1
ff0762:f8e11ab7f833bbe93bd13bbed3e30a3eaba9e34a4510e344abc93404c26d1801
ff0763:7e0a8c9844d0f99ec84307483f2e331980749f88a7185649d4d99fa3c3589e52
ff0764:ac25863ba43b96aea864ba2aa256022af9d38dc93e97437f3de603cc487306cb
ff0765:6bcb147d41e9b577f40002a5c4ba08846737805aafe8554dd0e72204f6007ba7
ff0766:2964fd3210ea68faa2b4a849b36243d33f74429d1b43ce019e7b154eac7759ba
ff0767:cb89b4b505dd2ff5edfce618359fd6e288ad7905c2486103ff56fcd1d5de1857
ff0768:76b27b80a58027dc3cf1da68dac17010ed93997d0b603e2fadbe85012493b5a7
ff0769:882d9924fc69a00574d54c2bb4014825a1c1c71fa1d0238cac865fe0aa4ad60b
ff076a:17832dbb48f609b722a27507f1d327de062d7f7b85b71325d8dd99b19fb5bad4
ff076b:07e5866107e24ae69a9679668f916aa1b3b39dc3554781e3ae9abaa44b5a7bc4
ff076c:6dd4e12b751849ba3e1ad90ac48674c2474c772182f3500c85c2df4db7f48866
ff076d:ed124f475aaf4d98d1e618d3be32f003b3cbb873c7d15b0f1a0089739cb4e4cc
ff076e:98380e437e1a46e6ac2aa64d7be6d71f2969e510acaf5d37846cf12b8afe7b3e
ff076f:076ea7358389410df85d911d251b9a582c5e6f684e0f046ed430187f0533aefc
ff0770:690dd5ab690009813339bc668c6d3839144f34e17e5be7f0958879e9a9e057fb
ff0771:a92bf1fdfb2da2a1ce60e7440992e53a410ce2faa8ab71ead7444f2486e5fa9f
ff0772:d65810ffd7bf9a0e5779df6753ba3894379f850b1b743aec55786f98ac29011f
ff0773:d7a43aab5b59f58cb68cc01cf838a392ee913ff330fe7c3309eda30b84541d07
ff0774:3296eb060c887e8ec0e59903e9cc8d5f6302ee8faba95620ae5de2364333f753
ff0775:4d391fc790bd702cad3ccbc0b025c5cdd88c6fdf274dcf5fbd3f027a80c2c7e5
ff0776:42e46c4487459128517649731457b6ae20099d541bd182c5497b2e67e6ffd0f6
ff0777:0a85075dd6b382eab31449823db8bed6b61a441714165e33faca42cd9c8dec2a
ff0778:2cf5539249a9e38fc010e29ff3e8046658f3d030b93310473687fa91f8da44ca
ff0779:a7d7285843b89b134f852cb52a6f431938257c826d699aa806c894a0a1cdb847
ff077a:3b83eb5d7a9a5af06275a0a1c1b35bd562622a5521e2699f25559328b8829058
ff077b:b723273a3506c6bed85f083da562734be09f2c47ade47317831d63aa8be278a5
ff077c:8346922cb8730bb6ae71ab03bfc42462f4160423d9079be64385621ac5877672
ff077d:9163f1910d4944be32d0d224a79f9fa6b4036e9098795ac81d3dd14ce4ff24d2
ff077e:6802701f0fd0960ff2b51f39aaeb20a778d83261a959ad0d7ff0be54240f673d
ff077f:ce75580bc6796d3b3ea2c3e74259d0d403072408e960c77139c2fb5a3d9419e4
ff0780:92f351bf3d54164dfa8dd8f9e1139d3150349786485d2b9eecd00e2971c1e6c5
ff0781:ea6b89ed6907a209ff9188676fb164e7aced894b8996dfbe5ce5bbcc22de4ddd
ff0782:a287ffab762cc69a26d482037edf701f653ce899025c62a7e5cb88bb9b419cbb
ff0783:54f8ca858bcc7591f28d8dc3772e9bc581717f3a23a288bfd405939c36208de5
ff0784:54c660da29d75fc81f07ad6dc8bb7aee2258e071e8b1077544fa5622ff44c99d
ff0785:9d5e86906a1680a86be278cf76e3d2b62b775186101461d303cee910d94ce13a
ff0786:1dfc1605fbad358d8bc844f76d15203fac9ca5c1a79fd4857ffaf2864fbebf96
ff0787:9c3f2fd11c57d7c649ad5a0932c0f0d29756f6a0a1c74c43e1e89a62d64cd320
ff0788:9f819a4c876e12dc84e6fe0e37c1a69b137094b453fa98449398f4b71f4d0092
ff0789:d0c97e56c7b0ba812d944ad771f7799b5d4144a2327a4e416554f7ee2aa0aeae
ff078a:812c212e9e45dc5005c7f47411183f5fb2ff1baee184d3354b2e93d78c280164
ff078b:b10b6f00e609509e8700f6d34687a2bfce38ea05a8fdf1cdc40c3a2a0d0d0e45
ff078c:e6fe22bf45e4f0d3b85c59e02c0f495418e1eb8d3210f788d48cd5e1cb547cd4
ff078d:2fe357db13751ff9160e87354975b3407498f41c9bd16a48657866e6e5a9b4c7
ff078e:dc9416c2f855126d6de977677538f2f967ff4998e90dfa435a17219be077fc06
ff078f:ae0fc852280f1b87cedaf73cfb84cf106efec88e8294253af352ed4034460d7b
ff0790:847409e63526f162753ac49f75218efaafa7d5c94ade9095ce72e7f6b6e3ac99
ff0791:6807c97235c5ec6090269a4b5fedfab46986e42f4d67d2edddcf6e45cf0dfa80
ff0792:72d716f7bb6bd105704f42b9524923510dcb85b2d870c0e9ada5aeb9c969051a
```