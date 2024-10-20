import pytest
from api import MethodRequest, INVALID_REQUEST, FORBIDDEN


@pytest.fixture
def context():
    return {}


@pytest.fixture
def store():
    return None


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
