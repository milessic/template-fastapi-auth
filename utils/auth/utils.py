import bcrypt
from typing import Annotated
import json
import jwt
from typing import Optional
from datetime import timedelta, datetime, UTC
from fastapi import HTTPException, Cookie, Depends, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from utils.controller import Controller

c = Controller()


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

async def get_token(
        access_token: str = Cookie(None),
        authorization: HTTPAuthorizationCredentials = Depends(HTTPBearer(auto_error=False)),
        Bearer: Annotated[str|None, Header()]=None,
        ):

    token = None
    # Prefer Authorization header if provided
    if authorization and authorization.scheme.lower() == "bearer":
        print(1)
        token = authorization.credentials
    elif access_token:
        token = access_token
    elif Bearer:
        token = Bearer

    if not token:
        raise HTTPException(status_code=401, detail="Token not provided")
    
    return verify_jwt_token(token)

def verify_jwt_token(token: str):
    try:
        payload = jwt.decode(token, c.SECRET_KEY, algorithms=[c.ALGORITHM])
        return payload  
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

