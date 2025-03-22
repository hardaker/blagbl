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
from collections import defaultdict
from logging import info, error
from pathlib import Path

COLUMN_NAMES = ["address", "ip_numeric", "ASN", "owner", "country", "ip_range"]
ASN_COLUMN_NAMES = ["ASN", "owner", "country", "ip_range"]

default_store = Path(os.environ["HOME"]).joinpath(".local/share/blag")


class BlagBL:
    def __init__(self, database: str = None, exit_on_error: bool = True):
        "Create an instance of the BLAG Block List manager."
        self._database = self.get_blag_path(database, exit_on_error)
        self.blag_list = None
        self.map_list = None
        self._ips = None

    @property
    def ips(self):
        """The extracted IP map from the BLAG archive."""
        return self._ips

    @ips.setter
    def ips(self, newval):
        self._ips = newval

    @property
    def database(self):
        """The storage location of the cached BLAG database."""
        return self._database

    @database.setter
    def database(self, newval):
        self._database = newval

    def get_blag_path(self, suggested_database: str, exit_on_error: bool = True):
        "Find the blag storage data if it exists."

        database: str = default_store.joinpath("blag.zip")

        if suggested_database and Path(suggested_database).is_file():
            database = suggested_database
        elif Path("blag.zip").is_file():
            info("using ./blag.zip")
            database = "blag.zip"
        elif database.is_file():
            info(f"using {database}")
        elif exit_on_error:
            error("Cannot find the blag storage directory.")
            error("Please specify a location with -d.")
            error(
                "Run with --fetch to use the default and download a copy using this tool."
            )
            error(f"Default storage location: {database}")
            sys.exit(1)

        return database

    def fetch(self, date_path: str = None):
        if not date_path:
            yesterday = dateparser.parse("yesterday")
            date_path = yesterday.strftime("%Y/%m/%Y-%m-%d.zip")

        request_url = "https://steel.isi.edu/projects/BLAG/data/" + date_path

        info(f"starting download")

        if not self.database.parent().is_dir():
            self.database.mkdir(parents=True)

        # fetch the contents to our storage location
        with requests.get(request_url, stream=True) as request:
            if request.status_code != 200:
                error(f"failed to fetch {request_url}")
                sys.exit(1)

            with self.database.open("wb") as storage:
                for chunk in request.iter_content(chunk_size=4096 * 16):
                    storage.write(chunk)

        info(f"saved data to {self.database}")

    def extract_blag_files(self):
        """Extract the individual files from within the BLAG zip archive."""
        zfile = zipfile.ZipFile(self.database)
        items = zfile.infolist()
        file_names = {"blag_list": items[1].filename, "map_list": items[2].filename}

        with zfile.open(file_names["blag_list"]) as blag_handle:
            blag_contents = blag_handle.read()

        with zfile.open(file_names["map_list"]) as map_handle:
            map_contents = map_handle.read()

        self.blag_list = blag_contents.decode("utf-8")
        self.map_list = map_contents.decode("utf-8")
        return (self.blag_list, self.map_list)

    def parse_blag_contents(self):
        """Extract the BLAG contents and map the results into a single dict."""
        if not self.blag_list or not self.map_list:
            self.extract_blag_files()

        map_csv = csv.reader(self.map_list.split())
        blag_map = {}
        for row in map_csv:
            blag_map[row[1]] = row[0]

        blag_csv = csv.reader(self.blag_list.split())
        ips = defaultdict(list)
        for row in blag_csv:
            ip = row.pop(0)
            ips[ip] = [blag_map[x] for x in row]

        self.ips = ips
        return ips


if __name__ == "__main__":
    main()
