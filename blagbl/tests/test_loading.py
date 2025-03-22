"""Test BlagBL."""
from collections import defaultdict
from blagbl import BlagBL


def test_basic_startup() -> None:
    """Test basic start up."""
    bl = BlagBL()
    bl.parse_blag_contents()

    assert isinstance(bl.ips, defaultdict)
    assert len(bl.ips) > 0
