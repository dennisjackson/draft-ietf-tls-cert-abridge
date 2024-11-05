import base64
import csv
import logging
import random

import numpy
import scipy
from tabulate import tabulate
from tqdm import tqdm

import schemes.abridged
from schemes.certs import load_cert_chains
import schemes.existing

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(message)s",
    datefmt="%H:%M",
)


def load_schemes():
    compressors = [
        # Existing Drafts
        schemes.existing.NullCompressor(),
        schemes.existing.TLSCertCompression(),
        schemes.existing.IntermediateSuppression(),
        schemes.existing.ICAAndTLS(),
        schemes.existing.HypotheticalOptimimum(),
        schemes.existing.MetadataEstimate(),
        schemes.existing.LeafDomainNames(),
        # This Draft
        schemes.abridged.PrefixOnly(),
        schemes.abridged.PrefixAndZstd(offlineCompression=False),
        schemes.abridged.PrefixAndZstd(offlineCompression=True),
        schemes.abridged.PrefixAndBrotli(),
        schemes.abridged.Baseline(offlineCompression=True),
        schemes.abridged.Baseline(offlineCompression=False),
    ]
    # Optimal when compared against dictionary sizes of 1k, 10k, 100k, 200k
    # Using redaction to avoid favouring certain websites
    compressors += [
        schemes.abridged.PrefixAndTrained(
            dict_size=3000, redact=True, offlineCompression=True
        )
    ]
    compressors += [
        schemes.abridged.PrefixAndTrained(
            dict_size=100000, redact=True, offlineCompression=True
        )
    ]

    # Optimal when compared against thresholds of 1,10,100 and 1000
    compressors += [schemes.abridged.PrefixAndCommon(threshold=2000)]

    compressors += [schemes.abridged.PrefixAndSystemic(offlineCompression=True)]
    compressors += [schemes.abridged.PrefixAndSystemic(offlineCompression=False)]
    return compressors


def load_chains():
    return random.sample(load_cert_chains(), 20000)


def benchmark(targets, chains):
    results = dict()
    for target in targets:
        results[target] = list()

    for entry in tqdm(chains, desc="Benchmarking Compression Schemes"):
        entry = [base64.b64decode(x) for x in entry]
        for scheme in targets:
            size = len(scheme.compress(entry))
            results[scheme].append(size)
    return results


def write_stats(results, out_path, stats):
    with open(out_path, "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(
            ["Scheme", "Storage Footprint"] + [name for name, _ in stats]
        )  # Write header row

        for scheme, sizes in tqdm(
            results.items(), desc="Computing Confidence Intervals"
        ):
            row = [scheme.name(), scheme.footprint()]
            for stat_name, stat_fun in stats:
                lower, upper = scipy.stats.bootstrap(
                    [sizes], stat_fun, method="percentile"
                ).confidence_interval
                if upper - lower > 100:
                    logging.warning(
                        f"Large CI for {scheme.name()}-{stat_name}: [{lower:.1f},{upper:.1f}]"
                    )
                row.append(stat_fun(sizes))
            writer.writerow(row)


def stats_to_md(in_path):
    with open(in_path, "r") as file:
        csv_reader = csv.reader(file)
        table_data = list(csv_reader)
    return tabulate(table_data, headers="firstrow", tablefmt="github", floatfmt=".0f")


def main():
    targets = load_schemes()
    chains = load_chains()
    logging.info(
        f"Evaluating {len(targets)} schemes on {len(chains)} certificate chains"
    )
    results = benchmark(targets, chains)
    stats = [(f"p{y}", lambda x, y=y: numpy.percentile(x, y)) for y in [5, 50, 95]]
    for scheme, result in results.items():
        results[scheme] = numpy.array(result)
    write_stats(results, "output.csv", stats)
    print()
    print(stats_to_md("output.csv"))


if __name__ == "__main__":
    # TODO Basic CLI Interface
    main()
