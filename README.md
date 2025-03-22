# About

This package is a BLAG block list lookup module and command line tool.
See the [BLAG webpage](https://steel.isi.edu/projects/BLAG) for
details on the BLAG aggregated blocklist.

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

# Module Usage

``` python
from blagbl import BlagBL

blag = BlagBL()
# blag.fetch()  # do this rarely
blag.parse_blag_contents()
print(blag.ips["112.207.220.102"])
```
