# About

This package is a BLAG block list lookup module and command line tool.
See the [BLAG webpage](https://steel.isi.edu/projects/BLAG) for
details on the BLAG aggregated blocklist.

# Installation

Install using `pip` or any of the other module management tools:

``` sh
$ pip install blagbl
```

# CLI Usage

Fetch the most recent dataset:

``` sh
$ blagbl --fetch
```

And use it to look up an address:

``` sh
$ blagbl 112.207.220.102
112.207.220.102                          cruzit_web_attacks
```

Display information about the current database:

``` sh
$ blagbl --info
Data from:           2025-03-27
IP Count:            1072961
```

# Module Usage

``` python
from blagbl import BlagBL

blag = BlagBL()
# blag.fetch()  # do this rarely
blag.parse_blag_contents()
print(blag.ips["112.207.220.102"])
```
