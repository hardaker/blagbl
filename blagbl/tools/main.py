"""Fetches and accesses contents of the BLAG blocklist set from USC/ISI."""

from __future__ import annotations
from argparse import ArgumentDefaultsHelpFormatter, Namespace
import argparse
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
        "--info", action="store_true", help="Display information about the dataset."
    )

    parser.add_argument(
        "-f",
        "--blag-database",
        type=str,
        default=default_store,
        help="The blag database file to use",
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

    log_level = args.log_level.upper()

    handlers = []
    datefmt = None
    messagefmt = "%(levelname)-10s:\t%(message)s"

    # see if we're rich
    try:
        handlers.append(
            RichHandler(
                rich_tracebacks=True,
                tracebacks_show_locals=True,
                console=Console(
                    stderr=True, theme=Theme({"logging.level.success": "green"})
                ),
            )
        )
        datefmt = " "
        messagefmt = "%(message)s"
    except Exception:
        debug("failed to install RichHandler")

    logging.basicConfig(
        level=log_level, format=messagefmt, datefmt=datefmt, handlers=handlers
    )

    return args


def main() -> None:
    """Implement the meat of the blag script."""
    args = parse_args()

    bl = BlagBL(args.blag_database, exit_on_error=(not args.fetch))

    if args.fetch:
        bl.fetch()
        return

    # read the zip file
    bl.parse_blag_contents()

    if args.info:
        print(f"{'Data from:':<20} {bl.save_date}")
        print(f"{'IP Count:':<20} {len(bl.ips)}")
        return

    for ip in args.addresses:
        print(f"{ip:<40} {', '.join(bl.ips[ip])}")


if __name__ == "__main__":
    main()
