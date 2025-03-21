#!/usr/bin/python3

"""Fetches and accesses contents of the BLAG blocklist set from USC/ISI."""

import argparse
import sys
import os
import time
import blagbl
import requests
import pyfsdb
import logging
import ipaddress
import dateparser
import zipfile
import csv
from logging import info, error
from pathlib import Path

COLUMN_NAMES = ["address", "ip_numeric", "ASN", "owner", "country", "ip_range"]
ASN_COLUMN_NAMES = ["ASN", "owner", "country", "ip_range"]

default_store = Path(os.environ["HOME"]).joinpath(".local/share/blag")


def parse_args():
    """Handles argument parsing for the blag script."""
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description="Describes one or more IP addresses from an blag database",
        epilog="""Example Usage: blag -f blag-v4-43.tsv 1.1.1.1""",
    )

    parser.add_argument(
        "--fetch", action="store_true", help="Fetch/update the cached BLAG dataset."
    )

    parser.add_argument(
        "-f",
        "--blag-database",
        type=str,
        default=default_store,
        help="The blag database file to use",
    )

    parser.add_argument(
        "-a",
        "--search-by-asn",
        action="store_true",
        help="Instead of searching by IP address, search by an ASN number instead and return all records for that ASN number",
    )

    parser.add_argument(
        "-A",
        "--asn-limit",
        type=int,
        default=0,
        help="Search by ASN, but limit the results to this number -- implies -a",
    )

    parser.add_argument(
        "-o",
        "--output-file",
        default=sys.stdout,
        type=argparse.FileType("w"),
        help="Output the results to this file",
    )

    parser.add_argument(
        "-F",
        "--output-fsdb",
        action="store_true",
        help="Output FSDB (tab-separated) formatted data",
    )

    parser.add_argument(
        "-T",
        "--output-pcap-filter",
        action="store_true",
        help="Output the results as a libpcap / tcpdump filter expression",
    )

    parser.add_argument(
        "-I",
        "--input-fsdb",
        type=argparse.FileType("r"),
        help="Read an input FSDB and add columns to it; implies -F as well",
    )

    parser.add_argument(
        "-k",
        "--key",
        default="key",
        type=str,
        help="The input key of the FSDB input file that contains the ip address to analyze",
    )

    parser.add_argument(
        "-C",
        "--cache-database",
        action="store_true",
        help="After loading the blag file, cache it in a msgpack file for faster loading next time.",
    )

    parser.add_argument(
        "--log-level",
        "--ll",
        default="info",
        help="Define the logging verbosity level (debug, info, warning, error, fotal, critical).",
    )

    parser.add_argument(
        "addresses", type=str, nargs="*", help="Addresses to print information about"
    )

    args = parser.parse_args()

    if args.asn_limit > 0:
        args.search_by_asn = True

    log_level = args.log_level.upper()
    logging.basicConfig(level=log_level, format="%(levelname)-10s:\t%(message)s")

    return args


def print_result(to, address, result):
    """Displays the results to the output terminal/stdout"""
    if "ip_numeric" in result:
        to.write("Address: {}\n".format(address))
        to.write("  Numeric ip: {}\n".format(result["ip_numeric"]))
    to.write("         ASN: {}\n".format(result["ASN"]))
    to.write("       Owner: {}\n".format(result["owner"]))
    to.write("     Country: {}\n".format(result["country"]))
    to.write("    ip_range: {}\n".format(result["ip_range"]))
    to.write("\n")


def output_fsdb_row(outf, address, result):
    if "ip_numeric" in result:
        outf.append(
            [
                address,
                result["ip_numeric"],
                result["ASN"],
                result["owner"],
                result["country"],
                result["ip_range"],
            ]
        )
    else:
        outf.append(
            [result["ASN"], result["owner"], result["country"], result["ip_range"]]
        )


def output_pcap_filter(results: list) -> None:
    sys.stdout.write("( ")
    expressions = []
    for result in results:
        (left, right) = result["ip_range"]
        if left <= 2**33:
            left = ipaddress.IPv4Address(left)
            right = ipaddress.IPv4Address(right)
        else:
            left = ipaddress.IPv6Address(left)
            right = ipaddress.IPv6Address(right)
        ranges = ipaddress.summarize_address_range(left, right)
        for range in ranges:
            expressions.append(f"net {range}")

    sys.stdout.write(" or ".join(expressions))
    print(" )")


def process_fsdb(i2a, inh, outh, key, by_asn=False):
    inf = pyfsdb.Fsdb(file_handle=inh)
    outf = pyfsdb.Fsdb(out_file_handle=outh)
    if by_asn:
        outf.out_column_names = inf.column_names + ASN_COLUMN_NAMES[1:]
    else:
        outf.out_column_names = inf.column_names + COLUMN_NAMES[1:]

    key_col = inf.get_column_number(key)
    for row in inf:
        if by_asn:
            results = i2a.lookup_asn(row[key_col], limit=1)
            if len(results) == 0:
                row.extend(["-", "-", "-", "-", "-"])
            else:
                row.extend(
                    [results[0]["owner"], results[0]["country"], results[0]["ip_range"]]
                )

        else:
            result = i2a.lookup_address(row[key_col])

            if result:
                row.extend(
                    [
                        result["ip_numeric"],
                        result["ASN"],
                        result["owner"],
                        result["country"],
                        result["ip_range"],
                    ]
                )
            else:
                row.extend(["-", "-", "-", "-", "-"])
        outf.append(row)


def get_blag_path(args, exit_on_error: bool = True):
    "Find the blag storage data if it exists."

    database: str = default_store.joinpath("blag.zip")

    if Path(args.blag_database).is_file():
        database = args.blag_database
    elif Path("blag.zip").is_file():
        info("using ./blag.zip")
        database = "blag.zip"
    elif database.is_file():
        info(f"using {database}")
    elif exit_on_error:
        error("Cannot find the blag storage directory.")
        error("Please specify a location with -d.")
        error("Run with --fetch to use the default and download a copy using this tool.")
        error(f"Default storage location: {database}")
        sys.exit(1)

    return database


def fetch_blag(storage_directory: str, date_path: str = None):
    if not date_path:
        yesterday = dateparser.parse("yesterday")
        date_path = yesterday.strftime("%Y/%m/%Y-%m-%d.zip")

    request_url = "https://steel.isi.edu/projects/BLAG/data/" + date_path

    info(f"starting download")

    if not isinstance(storage_directory, Path):
        storage_directory = Path(storage_directory)

    if not storage_directory.is_dir():
        storage_directory.mkdir(parents=True)

    zip_storage = storage_directory.joinpath("blag.zip")

    # fetch the contents to our storage location
    with requests.get(request_url, stream=True) as request:
        if request.status_code != 200:
            error(f"failed to fetch {request_url}")
            sys.exit(1)

        with zip_storage.open("wb") as storage:
            for chunk in request.iter_content(chunk_size=4096 * 16):
                storage.write(chunk)

    info(f"saved data to {zip_storage}")


def fetch_blag_files(storage_file: str):
    zfile = zipfile.ZipFile(storage_file)
    items = zfile.infolist()
    file_names = {"blag_list": items[1].filename, "map_list": items[2].filename}

    with zfile.open(file_names['blag_list']) as blag_handle:
        blag_contents = blag_handle.read()

    with zfile.open(file_names['map_list']) as map_handle:
        map_contents = map_handle.read()

    return (blag_contents.decode('utf-8'), map_contents.decode('utf-8'))


def parse_blag_contents(blag_list, map_list):
    
    map_csv = csv.reader(map_list.split())
    blag_map = {}
    for row in map_csv:
        blag_map[row[1]] = row[0]

    blag_csv = csv.reader(blag_list.split())
    ips = {}
    for row in blag_csv:
        ip = row.pop(0)
        ips[ip] = [blag_map[x] for x in row]

    return ips

def main():
    "The meat of the blag script"
    args = parse_args()

    database = get_blag_path(args, exit_on_error=(not args.fetch))

    if args.fetch:
        fetch_blag(database)
        sys.exit()

    # read the zip file
    (blag_list, map_list) = fetch_blag_files(database)

    # parse the contents
    ips = parse_blag_contents(blag_list, map_list)
    
    for ip in args.addresses:
        if ip in ips:
            print(f"{ip:<40} {', '.join(ips[ip])}")


if __name__ == "__main__":
    main()
