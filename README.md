# Abridged Certificate Compression for the WebPKI

This is the working area for the individual Internet-Draft, "Abridged Certificate Compression for the WebPKI".

This drafts defines WebPKI specific compression scheme for use in [TLS Certificate Compression](https://www.rfc-editor.org/rfc/rfc8879.html). The compression scheme relies on a static dictionary consisting of a snapshot of the root and intermediate certificates used in the WebPKI. The result is a dramatic improvement over the existing generic compression schemes used in TLS, equitable for both CAs and website operators and avoids the need for trust negotiation or additional error handling.

As the scheme removes the overhead of including root and intermediate certificates in the TLS handshake, it paves the way for a transition to PQ TLS certificates and has an outsized impact on QUIC's performance due to magnification limits on the server's response. This compression scheme may also be of interest in other situations where certificate chains are stored, for example in the operation of Certificate Transparency logs.

* [Editor's Copy](https://tlswg.github.io/draft-ietf-tls-cert-abridge/#go.draft-ietf-tls-cert-abridge.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-ietf-tls-cert-abridge)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-ietf-tls-cert-abridge)
* [Compare Editor's Copy to Individual Draft](https://tlswg.github.io/draft-ietf-tls-cert-abridge/#go.draft-ietf-tls-cert-abridge.diff)

## Preliminary Evaluation

| Scheme                                               |   p5 |   p50 |   p95 |
|------------------------------------------------------|------|-------|-------|
| Original / Uncompressed                              | 2308 |  4032 |  5609 |
| Existing TLS Certificate Compression                 | 1619 |  3243 |  3821 |
| **This Draft**                                       |  881 |  1256 |  1716 |
| Hypothetical Optimal Compression                     |  377 |   742 |  1075 |

A complete table of results and benchmarking scripts can be found in [benchmarks](benchmarks/).

## Contributing

See the [guidelines for contributions](https://github.com/tlswg/draft-ietf-tls-cert-abridge/blob/main/CONTRIBUTING.md).

Contributions can be made by creating pull requests. The GitHub interface supports creating pull requests using the Edit (✏) button.

Formatted text and HTML versions of the draft can be built using `make`. Command line usage requires that you have the necessary software installed.  See [the instructions](https://github.com/martinthomson/i-d-template/blob/main/doc/SETUP.md).
