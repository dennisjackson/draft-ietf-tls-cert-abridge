import logging

import zstandard
import brotli
from schemes.certs import is_ca_cert, report_missing_ca_cert, parse_der_to_cert

# TODO Using quick parameters during development
ZSTD_TRAINING_SPEED = 10
ZSTD_TRAINING_STEPS = 10


class DictCompress:
    def __init__(self, entries):
        self.compression_map = dict()
        self.decompression_map = dict()
        prefix = b"\x12\x34"
        for identifier, entry in enumerate(entries):
            entry_id = prefix + identifier.to_bytes(2, "big")
            self.compression_map[entry] = entry_id
            self.decompression_map[entry_id] = entry

    def name(self):
        return "Base: Dictionary Compressor"

    def compress(self, cert_chain):
        compressed = b""
        for cert_bytes in cert_chain:
            if cert_bytes in self.compression_map:
                compressed += self.compression_map[cert_bytes]
                continue
            else:
                parsed_cert = parse_der_to_cert(cert_bytes)
                if is_ca_cert(parsed_cert):
                    report_missing_ca_cert(parsed_cert)
                    # TODO: Assumes we will be including all commonly seen CA certs
                    compressed += b"\x12\x35\xff\xff"
                    continue
                compressed += cert_bytes
        return compressed

    def decompress(self, compressed_data):
        # TODO Not Implemented.
        pass


class ZstdWrapper:
    def __init__(self, shared_dict=None, offline_compression=False):
        # self.dictBytes = zstandard.ZstdCompressionDict(shared_dict)
        self.offlineCompression = offline_compression
        if offline_compression:
            params = zstandard.ZstdCompressionParameters(
                chain_log=30,
                search_log=30,
                hash_log=30,
                target_length=6000,
                threads=1,
                compression_level=22,
                force_max_window=1,
            )
        else:
            params = zstandard.ZstdCompressionParameters(
                threads=1,
                compression_level=3,
            )
        self.comp = zstandard.ZstdCompressor(
            compression_params=params, dict_data=shared_dict
        )

    def name(self):
        return f"Base: Zstandard + Offline Compression:{self.offlineCompression}"

    def compress(self, cert_chain):
        return self.compress_bytes(b"".join(cert_chain))

    def compress_bytes(self, raw_bytes):
        return self.comp.compress(raw_bytes)

    def decompress(self, compressed_data):
        # TODO Not Implemented
        return b""


def zstandard_train_dict(samples, target_size, offline_compression):
    logging.info(
        f"Training a zstd dictionary of {target_size} bytes over {len(samples)} samples"
    )
    return zstandard.train_dictionary(
        target_size,
        samples,
        level=22 if offline_compression else 3,
        notifications=1,
        threads=-1,
        accel=ZSTD_TRAINING_SPEED,
        steps=ZSTD_TRAINING_STEPS,
    )


class BrotliWrapper:
    def __init__(self):
        pass

    def name(self):
        return f"Base: Brotli"

    def compress(self, cert_chain):
        return self.compress_bytes(b"".join(cert_chain))

    def compress_bytes(self, raw_bytes):
        return brotli.compress(raw_bytes, quality=11, lgwin=17)

    def decompress(self, compressed_data):
        # TODO Not Implemented
        return b""
