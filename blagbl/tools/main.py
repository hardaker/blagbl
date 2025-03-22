"""Fetches and accesses contents of the BLAG blocklist set from USC/ISI."""

from __future__ import annotations
from argparse import  ArgumentDefaultsHelpFormatter, Namespace
import argparse
import sys
import os
import logging
from pathlib import Path
from blagbl import BlagBL
from logging import debug

# optionally use rich
try:
    from rich import print
    from rich.logging import RichHandler
    from rich.theme import Theme
    from rich.console import Console
except Exception:
    debug("install rich and rich.logging for prettier results")

# optionally use rich_argparse too
help_handler = ArgumentDefaultsHelpFormatter
try:
    from rich_argparse import RichHelpFormatter
    help_handler = RichHelpFormatter
except Exception:
    debug("install rich_argparse for prettier help")

default_store = Path(os.environ["HOME"]).joinpath(".local/share/blag/blag.zip")


def parse_args() -> Namespace:
    """Parse the command line arguments."""
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

    handlers = []
    datefmt = None
    messagefmt = "%(levelname)-10s:\t%(message)s"

    # see if we're rich
    try:
        handlers.append(RichHandler(rich_tracebacks=True,
                                    tracebacks_show_locals=True,
                                    console=Console(stderr=True,
                                                    theme=Theme({"logging.level.success": "green"}))))
        datefmt = " "
        messagefmt = "%(message)s"
    except Exception:
        debug("failed to install RichHandler")

    logging.basicConfig(level=log_level,
                        format=messagefmt,
                        datefmt=datefmt,
                        handlers=handlers)

    return args


def main() -> None:
    """Implement the meat of the blag script."""
    args = parse_args()

    bl = BlagBL(args.blag_database, exit_on_error=(not args.fetch))

    if args.fetch:
        bl.fetch()
        sys.exit()

    # read the zip file
    bl.parse_blag_contents()

    for ip in args.addresses:
        print(f"{ip:<40} {', '.join(bl.ips[ip])}")


if __name__ == "__main__":
    main()
