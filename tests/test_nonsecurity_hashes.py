"""Non-cryptographic identifiers keep working when security MD5 is disabled."""
import asyncio
import hashlib
from unittest.mock import AsyncMock

import pytest

from server import order_sync
from server.observability.db_spans import compute_oracle_sql_id


@pytest.fixture
def fips_hashes(monkeypatch):
    real_md5 = hashlib.md5
    def md5(data, *, usedforsecurity=True):
        if usedforsecurity:
            raise ValueError("MD5 is disabled for security use")
        return real_md5(data, usedforsecurity=False)
    monkeypatch.setattr(hashlib, "md5", md5)


def test_sql_identifier_works_with_security_md5_disabled(fips_hashes):
    assert compute_oracle_sql_id("select 1 from dual") == "fuwh2a749ds5a"


def test_synced_product_sku_works_with_security_md5_disabled(fips_hashes):
    class Session:
        def add(self, product):
            product.id = 1
        flush = AsyncMock()
    product = asyncio.run(order_sync._resolve_product(
        Session(), {"product_name": "Example Item", "unit_price": 3}, {}
    ))
    assert product.sku == "SYNC-CFC9665A"
    assert product.name == "Example Item"
