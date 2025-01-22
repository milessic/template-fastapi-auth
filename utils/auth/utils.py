import bcrypt
import json
import jwt
from typing import Optional
from datetime import timedelta, datetime, UTC

def hash_password(string:str):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(bytes(string, encoding="utf-8"),salt)

def unhash_password(password, hash) -> bool:
    return bcrypt.checkpw(bytes(password, encoding='utf-8'), hash)
    

def json_to_dict(obj):
    return json.loads(obj.json())

def generate_access_token(sub:str, secret_key, algorithm, expires_delta: Optional[timedelta] = None):
    if expires_delta:
        expire = datetime.now(UTC) + expires_delta
    else:
        expire = datetime.now(UTC) + timedelta(weeks=1)
    jwt_data = {"sub": sub, "exp": expire}
    return jwt.encode(jwt_data, secret_key)

def decode_access_token(token, secret_key, algorithm):
    return jwt.decode(token,secret_key, algorithms=[algorithm])

