
import pytest
from app import app, init_db, decrypt_key, encrypt_key
import jwt
from datetime import datetime, timezone
import sqlite3


@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_auth_request_logging(client):
    """Tests authentication request logging."""
    response = client.post('/auth', json={'username': 'testuser'})
    assert response.status_code == 200
    assert 'Authentication successful' in response.get_json().get('message', '')

def test_valid_JWT_authentication(client):
    """Tests that /auth returns a valid JWT."""
    response = client.post('/auth', json={'username': 'testuser'})
    assert response.status_code == 200
    token = response.get_json().get('token')
    assert token is not None
    decoded = jwt.decode(token, options={"verify_signature": False})
    assert decoded['Fullname'] == 'username'

def test_expired_JWT_authentication(client):
    """Tests that /auth returns an expired JWT when requested."""
    response = client.post('/auth', json={'username': 'testuser', 'expired': True})
    assert response.status_code == 200
    token = response.get_json().get('token')
    assert token is not None
    decoded = jwt.decode(token, options={"verify_signature": False, "verify_exp": False})
    assert decoded['exp'] < datetime.now(timezone.utc).timestamp()

def test_valid_JWK_found_in_JWKS(client):
    # Test to verify that JWT 'kid' matches one in the JWKS endpoint
    response = client.post('/auth', json={'username': 'testuser'})
    token = response.get_json().get('token')
    header = jwt.get_unverified_header(token)
    print("JWT Header Kid:", header['kid'])  # Debugging output

    jwks_response = client.get('/.well-known/jwks.json')
    jwks_keys = jwks_response.get_json()['keys']
    print("JWKS Kids:", [key['kid'] for key in jwks_keys])  # Debugging output

    assert any(key['kid'] == header['kid'] for key in jwks_keys), "No matching 'kid' found in JWKS keys."



def test_expired_JWK_not_found_in_JWKS(client):
    """Tests that an expired JWT's kid is not found in the JWKS keys."""
    response = client.post('/auth', json={'username': 'testuser', 'expired': True})
    token = response.get_json().get('token')
    header = jwt.get_unverified_header(token)

    jwks_response = client.get('/.well-known/jwks.json')
    jwks_keys = jwks_response.get_json()['keys']

    # Ensure that the 'kid' in the expired JWT header is NOT in the JWKS keys
    assert all(key['kid'] != header['kid'] for key in jwks_keys)

def test_encryption_decryption():
    """Tests the encryption and decryption functions."""
    original_text = 'testkey'
    encrypted_text = encrypt_key(original_text)
    decrypted_text = decrypt_key(encrypted_text)
    assert original_text == decrypted_text.decode('utf-8')
