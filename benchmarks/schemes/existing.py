from schemes.internal import ZstdWrapper
from schemes.certs import (
    is_ca_cert,
    parse_der_to_cert,
    get_all_ccadb_certs,
    extract_subject_info,
    extract_scts,
)
import zstandard


class NullCompressor:
    def __init__(self):
        pass

    def name(self):
        return "Original"

    def footprint(self):
        return 0

    def compress(self, cert_chain):
        return b"".join(cert_chain)

    def decompress(self, compressed_data):
        return compressed_data


class IntermediateSuppression:
    def __init__(self):
        self.known_certs = get_all_ccadb_certs()

    def name(self):
        return "Intermediate Suppression"

    def footprint(self):
        return 0

    def compress(self, cert_chain):
        byte_form = b""
        for der_bytes in cert_chain:
            parsed_cert = parse_der_to_cert(der_bytes)
            if is_ca_cert(parsed_cert):
                if der_bytes not in self.known_certs:
                    # Can't use ICA flag with CA cert not in root store
                    return b"".join(cert_chain)
                else:
                    # This cert will be suppressed
                    continue
            else:
                # Cert will be included
                byte_form += der_bytes
        return byte_form

    def decompress(self, compressed_data):
        return compressed_data


class TLSCertCompression:
    def __init__(self):
        self.inner = ZstdWrapper()

    def name(self):
        return "TLS Cert Compression"

    def footprint(self):
        return 0

    def compress(self, cert_chain):
        compressed_data = self.inner.compress(cert_chain)
        return compressed_data

    def decompress(self, compressed_data):
        decompressed_data = self.inner.decompress(compressed_data)
        return decompressed_data


class ICAAndTLS:
    def __init__(self):
        self.tls = TLSCertCompression()
        self.ica = IntermediateSuppression()

    def name(self):
        return "Intermediate Suppression and TLS Cert Compression"

    def footprint(self):
        return 0

    def compress(self, cert_chain):
        return self.tls.compress([self.ica.compress(cert_chain)])

    def decompress(self, compressed_data):
        return self.ica.decompress(self.tls.decompress(compressed_data))


class HypotheticalOptimimum:
    def __init__(self):
        pass

    def name(self):
        return "Hypothetical Optimal Compression"

    def footprint(self):
        return 0

    def compress(self, cert_chain):
        # TODO
        # Signature, Public Key and  zib compressed alternative names.
        (d, pk, s) = extract_subject_info(cert_chain[0])
        compressed_domains = zstandard.compress(d, 22)
        # SCTs
        return (
            compressed_domains
            + pk
            + s
            + b"".join([x.signature for x in extract_scts(cert_chain[0])])
        )

    def decompress(self, compressed_data):
        # Not defined.
        pass


class MetadataEstimate:
    def __init__(self):
        pass

    def name(self):
        return "Leaf Certificate Metadata Estimate"

    def footprint(self):
        return 0

    def compress(self, cert_chain):
        (d, pk, s) = extract_subject_info(cert_chain[0])
        compressed_domains = zstandard.compress(d, 22)
        # Size Estimate := Certificate - pk - sig with compressed_domains and no SCTs.
        size_estimate = (
            len(cert_chain[0]) - len(d) - len(pk) - len(s) + len(compressed_domains)
        )
        size_estimate -= sum(
            [len(x.signature) + len(x.log_id) for x in extract_scts(cert_chain[0])]
        )
        return b"x" * size_estimate

    def decompress(self, compressed_data):
        # Not defined.
        pass


class LeafDomainNames:
    def __init__(self):
        pass

    def name(self):
        return "Leaf Certificate Compressed Domains Estimate"

    def footprint(self):
        return 0

    def compress(self, cert_chain):
        (d, pk, s) = extract_subject_info(cert_chain[0])
        compressed_domains = zstandard.compress(d, 22)
        return compressed_domains

    def decompress(self, compressed_data):
        # Not defined.
        pass
