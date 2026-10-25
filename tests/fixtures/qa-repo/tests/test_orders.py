import time

import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_list_orders():
    r = client.get("/orders")
    assert r.status_code == 200


def test_orders_no_assert():
    client.get("/orders")


@pytest.mark.skip(reason="flaky")
def test_orders_skipped():
    assert False


def test_slow():
    time.sleep(2)
    assert True
