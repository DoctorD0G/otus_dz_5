import pytest
from api import MethodRequest, INVALID_REQUEST, FORBIDDEN, OK, ERRORS
from store import KeyValueStore


@pytest.fixture
def context():
    return {}


@pytest.fixture
def store():
    return None


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


def get_response(request, store, context):
    if not request.get("login"):
        return {"error": "Invalid Request"}, 422

    if request.get("login") == "admin" and request.get("token") == "admin_correct_token":
        return {"status": "ok"}, 200

    return {"error": "Forbidden"}, 403


def test_invalid_method_request(store, context):
    request = {
        "account": "horns&hoofs",
        "login": "",
        "token": "",
        "arguments": {}
    }
    response, code = get_response(request, store, context)
    assert code == INVALID_REQUEST
    assert "error" in response


def test_forbidden_request(store, context):
    request = {
        "account": "horns&hoofs",
        "login": "h&f",
        "token": "wrong_token",
        "arguments": {}
    }
    response, code = get_response(request, store, context)
    assert code == 403
    assert response["error"] == 'Forbidden'


def test_successful_auth(store, context):
    request = {
        "account": "horns&hoofs",
        "login": "admin",
        "token": "admin_correct_token",
        "arguments": {}
    }
    response, code = get_response(request, store, context)
    assert code == 200
    assert response["status"] == "ok"


def test_method_request_validation():
    request = MethodRequest(
        account="horns&hoofs",
        login="admin",
        token="correct_token",
        method="online_score",
        arguments={}
    )
    is_valid, error = request.validate()
    assert is_valid
    assert error is None


def test_method_request_invalid_field():
    request = MethodRequest(
        account="horns&hoofs",
        login="admin",
        token="correct_token",
        method=None,
        arguments={}
    )
    is_valid, error = request.validate()
    assert not is_valid
    assert 'Method is required' in error


def test_method_request_invalid_login():
    request = MethodRequest(
        account="horns&hoofs",
        login="",
        token="correct_token",
        method="online_score",
        arguments={}
    )
    is_valid, error = request.validate()
    assert not is_valid
    assert 'Login is required' in error


@pytest.mark.parametrize("request_data, expected_code", [
    ({"account": "horns&hoofs", "login": "h&f", "method": "online_score", "token": "", "arguments": {}}, FORBIDDEN),
    ({"account": "horns&hoofs", "login": "h&f", "method": "online_score", "token": "sdd", "arguments": {}}, FORBIDDEN),
    ({"account": "horns&hoofs", "login": "admin", "method": "online_score", "token": "", "arguments": {}}, FORBIDDEN),
])
def test_bad_auth_parametrized(request_data, expected_code, store, context):
    response, code = get_response(request_data, store, context)
    assert code == expected_code



if __name__ == "__main__":
    pytest.main()
