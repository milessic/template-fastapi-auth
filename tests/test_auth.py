import random
import json
import string
from fastapi.testclient import TestClient
from main import app
from utils.auth.utils import decode_token

client = TestClient(app)

auth_prefix = "/api/auth/"

username = ''.join(random.choice(string.ascii_lowercase) for _ in range(7))
email = username + "@test.com"
username2 = username + "us2"
email2 = username2 + "@test.com"
username3 = username + "us3"
email3 = username3 + "@test.com"
valid_password = "ValidPass123!"

# register
def test_register():
    response = client.post(auth_prefix + "register", json={
        "username": username,
        "password": valid_password,
        "email": email
    })
    assert response.status_code == 200
    assert response.json() == {"message": "registered"}

def test_register_with_existing_username_but_in_other_lettercase():
    response = client.post(auth_prefix + "register", json={
        "username": username.lower(),
        "password": valid_password,
        "email": "w" + email
    })
    assert response.status_code == 400

def test_register_with_existing_email_but_in_other_lettercase():
    response = client.post(auth_prefix + "register", json={
        "username": "wwe"+username.lower(),
        "password": valid_password,
        "email": email.upper()
    })
    assert response.status_code == 400
def test_register_with_existing_username():
    response = client.post(auth_prefix +"register", json={
        "username": username,
        "password": valid_password,
        "email": "q"+email
    })
    assert response.status_code == 400

def test_register_with_existing_email():
    response = client.post(auth_prefix +"register", json={
        "username": "q"+username,
        "password": valid_password,
        "email": email
    })
    assert response.status_code == 400

def test_register_with_to_short_password():
    response = client.post(auth_prefix +"register", json={
        "username": "qw"+username,
        "password": "abc1!",
        "email": "qw"+email
    })
    assert response.status_code == 400

# login
def test_login_with_username_success():
    response = client.post(auth_prefix + "token", data={
            "username": username,
            "password": valid_password
        },
                           headers={"Content-Type":"application/x-www-form-urlencoded"}

                           )
    resp_json = json.loads(response.text)
    assert "access_token" in resp_json
    assert decode_token(resp_json.get("access_token")).get("sub") == username


def test_email_with_username_success():
    response = client.post(auth_prefix + "register", json={
        "username": username2,
        "password": valid_password,
        "email": email2
    })
    assert response.status_code == 200
    assert response.json() == {"message": "registered"}
    response = client.post(auth_prefix + "token", data={
            "username": email2,
            "password": valid_password
        },
                           headers={"Content-Type":"application/x-www-form-urlencoded"}

                           )
    resp_json = json.loads(response.text)
    assert "access_token" in resp_json
    assert decode_token(resp_json.get("access_token")).get("sub") == username2

def test_tokens_generated_to_quickly():
    response = client.post(auth_prefix + "register", json={
        "username": username3,
        "password": valid_password,
        "email": email3
    })
    assert response.status_code == 200
    assert response.json() == {"message": "registered"}
    result = False
    for i in range(3):
        response = client.post(auth_prefix + "token", data={
                "username": email3,
                "password": valid_password
            },
                               headers={"Content-Type":"application/x-www-form-urlencoded"}

                               )
        resp_json = json.loads(response.text)
        if i == 0:
            assert response.status_code == 200
            assert "access_token" in resp_json
            assert decode_token(resp_json.get("access_token")).get("sub") == username3
            continue
        if response.status_code == 200:
            continue
        assert response.status_code == 400
        assert resp_json.get("detail") == "Access Token already exists! You may be generating it too fast!"
        result = True
    assert result

# endpoint with auth
def test_check_endpoint_with_auth_via_cookie():
    response = client.post(auth_prefix + "token", data={
            "username": username,
            "password": valid_password
        },
                           headers={"Content-Type":"application/x-www-form-urlencoded"}

                           )
    resp_json = json.loads(response.text)
    assert "access_token" in resp_json
    access_token = resp_json.get("access_token")
    assert decode_token(access_token).get("sub") == username

    # check /auth/me - 200
    resp_auth_me = client.get(auth_prefix + "me", cookies={"access_token":access_token})
    assert resp_auth_me.status_code == 200

    # check /auth/me - 401
    resp_auth_me = client.get(auth_prefix + "me")
    assert resp_auth_me.status_code == 401


def test_check_endpoint_with_auth_via_cookie():
    response = client.post(auth_prefix + "token", data={
            "username": username,
            "password": valid_password
        },
                           headers={"Content-Type":"application/x-www-form-urlencoded"}

                           )
    resp_json = json.loads(response.text)
    assert "access_token" in resp_json
    access_token = resp_json.get("access_token")
    assert decode_token(access_token).get("sub") == username

    # check /auth/me - 200
    resp_auth_me = client.get(auth_prefix + "me", headers={"Bearer":access_token})
    assert resp_auth_me.status_code == 200

    # check /auth/me - 401
    resp_auth_me = client.get(auth_prefix + "me")
    assert resp_auth_me.status_code == 401


