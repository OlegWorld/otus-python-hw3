import time

import pytest

import store


@pytest.fixture
def storage(request):
    return store.Store(max_attempts=10, max_timeout=1, max_workers=3)


def test_init_store(storage):
    storage.cache_set('key', 'value', 2)
    assert storage.cache_get('key') == 'value'
    time.sleep(3)
    assert not storage.cache_get('key')
    storage.stop()