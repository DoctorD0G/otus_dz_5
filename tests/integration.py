import pytest
from store import KeyValueStore


@pytest.fixture
def kv_store(mocker):
    store = KeyValueStore(host='localhost', port=6379, db=0, retries=3, timeout=1)
    return store


def test_cache_set(kv_store, mocker):
    key = "test_key"
    value = "test_value"
    expire = 60

    kv_store.connection.setex = mocker.MagicMock(return_value=True)
    kv_store.cache_set(key, value, expire)
    kv_store.connection.setex.assert_called_once_with(key, expire, value)


def test_cache_get_success(kv_store, mocker):
    key = "test_key"
    expected_value = "test_value"
    kv_store.connection.get = mocker.MagicMock(return_value=expected_value)
    result = kv_store.cache_get(key)
    assert result == expected_value
    kv_store.connection.get.assert_called_once_with(key)


def test_cache_get_failure(kv_store, mocker):
    key = "test_key"
    kv_store.connection.get = mocker.MagicMock(side_effect=Exception("Connection error"))
    kv_store.connect = mocker.MagicMock(return_value=kv_store.connection)
    with pytest.raises(ConnectionError):
        kv_store.cache_get(key)

    kv_store.connect.assert_called_once()


def test_get(kv_store, mocker):
    key = "test_key"
    expected_value = "test_value"
    kv_store.connection.get = mocker.MagicMock(return_value=expected_value)
    result = kv_store.get(key)

    assert result == expected_value
    kv_store.connection.get.assert_called_once_with(key)


def test_get_reconnect(kv_store, mocker):
    key = "test_key"
    kv_store.connection.get = mocker.MagicMock(side_effect=[Exception("Connection error"), "test_value"])
    kv_store.connect = mocker.MagicMock(return_value=kv_store.connection)
    result = kv_store.get(key)

    assert result == "test_value"
    kv_store.connect.assert_called_once()


if __name__ == "__main__":
    pytest.main()
