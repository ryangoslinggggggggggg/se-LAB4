import pytest
from app import app, init_db


@pytest.fixture
def client(tmp_path):
    test_db = tmp_path / "test.db"

    app.config["TESTING"] = True
    app.config["DATABASE"] = str(test_db)

    init_db()

    with app.test_client() as client:
        yield client


def test_valid_login(client):
    response = client.post(
        "/login",
        data={
            "username": "student",
            "password": "Password123!"
        }
    )

    assert response.status_code == 200
    assert b"Login successful" in response.data


def test_bad_username(client):
    response = client.post(
        "/login",
        data={
            "username": "wronguser",
            "password": "Password123!"
        }
    )

    assert response.status_code == 401
    assert b"Invalid username or password" in response.data


def test_wrong_password(client):
    response = client.post(
        "/login",
        data={
            "username": "student",
            "password": "WrongPassword!"
        }
    )

    assert response.status_code == 401
    assert b"Invalid username or password" in response.data


def test_empty_fields(client):
    response = client.post(
        "/login",
        data={
            "username": "",
            "password": ""
        }
    )

    assert response.status_code == 400
    assert b"Username and password are required" in response.data


def test_sql_injection(client):
    response = client.post(
        "/login",
        data={
            "username": "' OR '1'='1",
            "password": "' OR '1'='1"
        }
    )

    assert response.status_code == 401
    assert b"Invalid username or password" in response.data


def test_account_lockout(client):
    for _ in range(3):
        response = client.post(
            "/login",
            data={
                "username": "student",
                "password": "WrongPassword!"
            }
        )

    assert response.status_code == 423
    assert b"Account temporarily locked" in response.data


def test_locked_account_rejects_login(client):
    for _ in range(3):
        client.post(
            "/login",
            data={
                "username": "student",
                "password": "WrongPassword!"
            }
        )

    response = client.post(
        "/login",
        data={
            "username": "student",
            "password": "Password123!"
        }
    )

    assert response.status_code == 423
    assert b"Account temporarily locked" in response.data


def test_username_case_insensitive(client):
    response = client.post(
        "/login",
        data={
            "username": "STUDENT",
            "password": "Password123!"
        }
    )

    assert response.status_code == 200
    assert b"Login successful" in response.data