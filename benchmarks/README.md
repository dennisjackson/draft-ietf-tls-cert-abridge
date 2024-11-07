# Benchmarks

This folder contains scripts for benchmarking the various compression schemes.

| Scheme                                                                                          |   Storage Footprint |   p5 |   p50 |   p95 |
|-------------------------------------------------------------------------------------------------|---------------------|------|-------|-------|
| Original                                                                                        |                   0 | 2308 |  4031 |  5636 |
| TLS Cert Compression                                                                            |                   0 | 1673 |  3319 |  3963 |
| Intermediate Suppression                                                                        |                   0 | 1316 |  1689 |  4220 |
| Intermediate Suppression and TLS Cert Compression                                               |                   0 | 1035 |  1467 |  3370 |
| Hypothetical Optimal Compression                                                                |                   0 |  380 |   746 |  1078 |
| Leaf Certificate Metadata Estimate                                                              |                   0 |  568 |   721 |  1072 |
| Leaf Certificate Compressed Domains Estimate                                                    |                   0 |   25 |    39 |   273 |
| CA Prefix Only                                                                                  |                   0 | 1005 |  1440 |  2498 |
| Base: Dictionary Compressor Base: Zstandard + Offline Compression:False                         |                   0 |  877 |  1293 |  1797 |
| Base: Dictionary Compressor Base: Zstandard + Offline Compression:True                          |                   0 |  868 |  1286 |  1757 |
| **This Draft                                                     |                   0 |  881 |  1256 |  1716 |
| Method 1: Baseline Base: Zstandard + Offline Compression:True                                   |             3455467 |  721 |  1095 |  1633 |
| Method 1: Baseline Base: Zstandard + Offline Compression:False                                  |             3455467 | 1179 |  2874 |  3344 |
| Method 2: CA Prefix with Training redacted=True, offlineComp=True                               |                3000 |  582 |   959 |  1538 |
| Method 2: CA Prefix with Training redacted=True, offlineComp=True                               |              100000 |  548 |   931 |  1393 |
| Method 2: CA Prefix and CommonStrings threshold=2000 Base: Zstandard + Offline Compression:True |                1848 |  724 |  1131 |  1641 |
| Method 2: CA Prefix and SystematicStrings Base: Zstandard + Offline Compression:True            |               65336 |  661 |  1061 |  1447 |
| Method 2: CA Prefix and SystematicStrings Base: Zstandard + Offline Compression:False           |               65336 |  690 |  1087 |  1515 |

## Methodology

These compression schemes are defined in the associated scripts in the schemes folder. Each scheme is evaluated over a sample of certificate chains fetched from the Tranco top 100k. The confidence interval for each percentile is calculated and the upper bound is taken.