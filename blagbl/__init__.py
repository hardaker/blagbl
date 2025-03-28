"""Fetches and accesses contents of the BLAG blocklist set from USC/ISI."""

from __future__ import annotations
import sys
import os
import requests
import dateparser
import zipfile
import csv
import msgpack
from collections import defaultdict
from logging import info, error, warning
from pathlib import Path

__VERSION__ = "0.1.1"

CACHE_VERSION: int = 1
DEFAULT_STORE: Path = Path(os.environ["HOME"]).joinpath(".local/share/blag")


class BlagBL:
    """A class for loading and parsing BLAG block list data."""

    def __init__(self, database: str = None, exit_on_error: bool = True):
        """Create an instance of the BLAG Block List manager."""
        self._database = self.get_blag_path(database, exit_on_error)
        self.blag_list = None
        self.map_list = None
        self._save_date = None
        self._ips = None

    @property
    def ips(self) -> defaultdict:
        """The extracted IP map from the BLAG archive."""
        return self._ips

    @ips.setter
    def ips(self, newval: defaultdict) -> None:
        self._ips = newval

    @property
    def database(self) -> str:
        """The storage location of the cached BLAG database."""
        return self._database

    @database.setter
    def database(self, newval: str) -> None:
        self._database = newval

    @property
    def save_date(self) -> str:
        """The date the blocklist is from."""
        return self._save_date

    @save_date.setter
    def save_date(self, newval: str) -> None:
        self._save_date = newval

    def get_blag_path(self, suggested_database: str, exit_on_error: bool = True) -> str:
        """Find the blag storage data if it exists."""
        database: str = DEFAULT_STORE.joinpath("blag.zip")

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

    def fetch(self, date: str = None) -> None:
        """Fetch the BLAG list from the blag web server."""
        if not date:
            date = dateparser.parse("yesterday")
        date_path = date.strftime("%Y/%m/%Y-%m-%d.zip")
        self.save_date = date.strftime("%Y-%m-%d")

        request_url = "https://steel.isi.edu/projects/BLAG/data/" + date_path

        info("starting download")

        if not self.database.parent.is_dir():
            self.database.mkdir(parents=True)

        # fetch the contents to our storage location
        with requests.get(request_url, stream=True) as request:
            if request.status_code != 200:
                error(f"failed to fetch {request_url}")
                sys.exit(1)

            with self.database.open("wb") as storage:
                for chunk in request.iter_content(chunk_size=4096 * 16):
                    storage.write(chunk)

        self.parse_blag_contents()  # parses and saves the cached version
        info(f"saved data to {self.database}")

    def extract_blag_files(self) -> tuple:
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

    def parse_blag_contents(self, save_cache: bool = True) -> defaultdict:
        """Extract the BLAG contents and map the results into a single dict."""
        if not self.blag_list or not self.map_list:
            # try to load from the cache first:
            if self.load_cache():
                return self.ips

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
        if save_cache:
            self.save_cache()
        return ips

    def save_cache(self, location: str = None) -> None:
        """Save the current data to a msgpack cache file for faster loading."""
        if not location:
            location = str(self.database) + ".msgpack"
        with Path.open(location, "wb") as cache_file:
            msgpack.dump(
                {"version": CACHE_VERSION, "ips": self.ips, "date": self.save_date},
                cache_file,
            )

    def load_cache(self, location: Path = None) -> defaultdict:
        """Load the cached data from disk."""
        if not location:
            location = Path(str(self.database) + ".msgpack")

        if not location.is_file():
            return None

        with location.open("rb") as cache_file:
            cache_info = msgpack.load(cache_file)

            if cache_info["version"] != CACHE_VERSION:
                warning("warning: cache version number differs -- things may break")

            self.ips = defaultdict(list)
            self.ips.update(cache_info["ips"])
            self.save_date = cache_info.get("date", "unknown")

        return self.ips
