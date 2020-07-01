import time

import pytest

import store


@pytest.fixture
def storage(request):
    return store.Store(None, max_attempts=10, max_timeout=1)


def test_init_store(storage):
    import redis
    help(redis)