from schemes.internal import (
    ZstdWrapper,
    DictCompress,
    BrotliWrapper,
    zstandard_train_dict,
)
from schemes.certs import (
    load_ee_certs_from_chains,
    CommonCertStrings,
    get_all_ccadb_certs,
    extract_cert_common_strings,
    extract_scts,
    get_cert_issuer,
)
import zstandard

# TODO: These footprints don't reflect any additional storage caused by
#       storing CA certs from outside the client's current root store.


class Baseline:
    def __init__(self, offlineCompression):
        ccadb_dict = b"".join(get_all_ccadb_certs())
        self.dict_size = len(ccadb_dict)
        self.inner = ZstdWrapper(
            zstandard.ZstdCompressionDict(ccadb_dict),
            offline_compression=offlineCompression,
        )

    def name(self):
        return "Method 1: Baseline " + self.inner.name()

    def footprint(self):
        return self.dict_size

    def compress(self, cert_chain):
        return self.inner.compress(cert_chain)

    def decompress(self, compressed_data):
        return self.inner.decompress(compressed_data)


class PrefixAndZstd:
    def __init__(self, offlineCompression):
        self.inner1 = DictCompress(get_all_ccadb_certs())
        self.inner2 = ZstdWrapper(offline_compression=offlineCompression)

    def footprint(self):
        return 0

    def name(self):
        return self.inner1.name() + " " + self.inner2.name()

    def compress(self, cert_chain):
        return self.inner2.compress_bytes(self.inner1.compress(cert_chain))

    def decompress(self, compressed_data):
        return self.inner1.decompress(self.inner2.decompress(compressed_data))


class PrefixAndBrotli:
    def __init__(self):
        self.inner1 = DictCompress(get_all_ccadb_certs())
        self.inner2 = BrotliWrapper()

    def footprint(self):
        return 0

    def name(self):
        return self.inner1.name() + " " + self.inner2.name()

    def compress(self, cert_chain):
        return self.inner2.compress_bytes(self.inner1.compress(cert_chain))

    def decompress(self, compressed_data):
        return self.inner1.decompress(self.inner2.decompress(compressed_data))


class PrefixOnly:
    def __init__(self):
        self.inner1 = DictCompress(get_all_ccadb_certs())

    def footprint(self):
        return 0

    def name(self):
        return "CA Prefix Only"

    def compress(self, cert_chain):
        return self.inner1.compress(cert_chain)

    def decompress(self, compressed_data):
        return self.inner1.decompress(compressed_data)


class PrefixAndTrained:
    def __init__(self, dict_size, redact, offlineCompression):
        self.redact = redact
        self.offlineComp = offlineCompression
        self.dict_size = dict_size
        self.inner1 = DictCompress(get_all_ccadb_certs())
        self.inner2 = ZstdWrapper(
            shared_dict=zstandard_train_dict(
                load_ee_certs_from_chains(self.redact),
                dict_size,
                offline_compression=False,
            ),
            offline_compression=False,
        )

    def footprint(self):
        return self.dict_size

    def name(self):
        return f"Method 2: CA Prefix with Training redacted={self.redact}, offlineComp={self.offlineComp}"

    def compress(self, cert_chain):
        return self.inner2.compress_bytes(self.inner1.compress(cert_chain))

    def decompress(self, compressed_data):
        return self.inner1.decompress(self.inner2.decompress(compressed_data))


class PrefixAndCommon:
    def __init__(self, threshold):
        self.inner1 = DictCompress(get_all_ccadb_certs())
        self.threshold = threshold
        common_dict = self.build_dict(threshold)
        self.dict_size = len(common_dict)
        self.inner2 = ZstdWrapper(shared_dict=common_dict, offline_compression=True)

    def name(self):
        return (
            f"Method 2: CA Prefix and CommonStrings threshold={self.threshold} "
            + self.inner2.name()
        )

    def footprint(self):
        return self.dict_size

    def compress(self, cert_chain):
        return self.inner2.compress_bytes(self.inner1.compress(cert_chain))

    def decompress(self, compressed_data):
        return self.inner1.decompress(self.inner2.decompress(compressed_data))

    def build_dict(self, threshold):
        cert_strings = CommonCertStrings(threshold)
        cert_strings.ingest_all(load_ee_certs_from_chains(redact=False))
        return zstandard.ZstdCompressionDict(cert_strings.top())


class PrefixAndSystemic:
    def __init__(self, offlineCompression):
        self.inner1 = DictCompress(get_all_ccadb_certs())
        common_dict = self.build_dict()
        self.dict_size = len(common_dict)
        self.inner2 = ZstdWrapper(
            shared_dict=common_dict, offline_compression=offlineCompression
        )

    def name(self):
        return f"Method 2: CA Prefix and SystematicStrings " + self.inner2.name()

    def footprint(self):
        return self.dict_size

    def compress(self, cert_chain):
        return self.inner2.compress_bytes(self.inner1.compress(cert_chain))

    def decompress(self, compressed_data):
        return self.inner1.decompress(self.inner2.decompress(compressed_data))

    def build_dict(self):
        string_dict = dict()
        string_dict[b"sct_log_ids"] = set()
        string_dict[b"issuer_names"] = set()
        for x in load_ee_certs_from_chains(redact=False):
            common_strings = extract_cert_common_strings(x)
            issuer_name = get_cert_issuer(x)
            if issuer_name not in string_dict:
                string_dict[issuer_name] = set()
            string_dict.get(issuer_name).update(common_strings)
            string_dict.get(b"sct_log_ids").update([x.log_id for x in extract_scts(x)])
            string_dict[b"issuer_names"].add(issuer_name)

        uniques = set()
        for v in string_dict.values():
            uniques.update(v)
        return zstandard.ZstdCompressionDict(b"".join(uniques))
