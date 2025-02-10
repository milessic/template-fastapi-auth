import bcrypt
import uuid
from typing import Annotated
import json
import jwt
from typing import Optional
from datetime import timedelta, datetime, UTC
from fastapi.responses import RedirectResponse
from fastapi import HTTPException, Cookie, Depends, Header, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from utils.controller import Controller
from string import ascii_lowercase, ascii_uppercase, ascii_letters
from random import SystemRandom, choice
from pydantic import BaseModel

from utils.auth.exceptions import *

c = Controller()


def hash_password(string:str):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(bytes(string, encoding="utf-8"),salt)

def unhash_password(password, hash) -> bool:
    return bcrypt.checkpw(bytes(password, encoding='utf-8'), hash)
    

def json_to_dict(obj:BaseModel|str):
    if isinstance(obj, BaseModel):
        return json.loads(obj.model_dump_json())
    return json.loads(obj)

def generate_access_token(sub:str, controller:Controller=c):
    expire = datetime.now(UTC) + timedelta(minutes=controller.ACCESS_TOKEN_EXPIRES_MINUTES)
    jwt_data = {"sub": sub, "exp": expire}
    token = jwt.encode(jwt_data, controller.SECRET_KEY)
    user_id = controller.db.get_user_id_from_username(sub)
    if user_id is None:
        raise HTTPException(500, {"msg": "Oopsie, user_id not found for '{sub}'!"})
    controller.db.create_access_token_record(token, user_id, get_epoch_now() + 60*controller.ACCESS_TOKEN_EXPIRES_MINUTES)
    return token

def generate_refresh_token(sub:str, controller:Controller=c):
    expire = datetime.now(UTC) + timedelta(minutes=controller.REFRESH_TOKEN_EXPIRES_MINUTES)
    jwt_data = {"sub": sub, "exp": expire}
    token = jwt.encode(jwt_data, controller.SECRET_KEY)
    user_id = controller.db.get_user_id_from_username(sub)
    if user_id is None:
        raise HTTPException(500, {"msg": "Oopsie, user_id not found for '{sub}'!"})
    controller.db.create_refresh_token_record(token, user_id, get_epoch_now() + 60*controller.REFRESH_TOKEN_EXPIRES_MINUTES)
    return token


def decode_token(token, controller:Controller=c):
    return jwt.decode(token,controller.SECRET_KEY, algorithms=[controller.ALGORITHM])

async def get_access_token(
        access_token: str = Cookie(None),
        authorization: HTTPAuthorizationCredentials = Depends(HTTPBearer(auto_error=False)),
        Bearer: Annotated[str|None, Header()]=None,
        ):

    token = None
    # Prefer Authorization header if provided
    if authorization and authorization.scheme.lower() == "bearer":
        token = authorization.credentials
    elif access_token:
        token = access_token
    elif Bearer:
        token = Bearer
    if not token:
        raise HTTPException(status_code=401, detail="Token not provided")
    return verify_access_token(token)

async def get_access_token_or_return_to_homepage(
        refresh_token: str = Cookie(None),
        authorization: HTTPAuthorizationCredentials = Depends(HTTPBearer(auto_error=False)),
        Bearer: Annotated[str|None, Header()]=None,
        ):

    token = None
    # Prefer Authorization header if provided
    if authorization and authorization.scheme.lower() == "bearer":
        token = authorization.credentials
    elif refresh_token:
        token = refresh_token 
    elif Bearer:
        token = Bearer
    if not token:
        raise HTTPException(status_code=401, detail="Token not provided")
    try:
        return verify_jwt_token(token, "refresh")
    except HTTPException:
        return {"return_to_homepage": True}

async def get_refresh_token(
        refresh_token: str = Cookie(None),
        authorization: HTTPAuthorizationCredentials = Depends(HTTPBearer(auto_error=False)),
        Bearer: Annotated[str|None, Header()]=None,
        ):

    token = None
    # Prefer Authorization header if provided
    if authorization and authorization.scheme.lower() == "bearer":
        token = authorization.credentials
    elif refresh_token:
        token = refresh_token 
    elif Bearer:
        token = Bearer
    if not token:
        raise HTTPException(status_code=401, detail="Token not provided")
    return verify_jwt_token(token, "refresh")


def verify_access_token(token: str, controller:Controller=c):
    return verify_jwt_token(token, "access", controller)

def verify_jwt_token(token:str, scenario:str, controller:Controller=c):
    try:
        payload = jwt.decode(token, c.SECRET_KEY, algorithms=[c.ALGORITHM])
        user_id = c.db.get_user_id_from_username(payload.get('sub'))
        if user_id is None:
            raise HTTPException(500, {"msg": "Oopsie, user_id not found for '{sub}'!"})
        if scenario.startswith("access") and \
                not c.db.check_if_access_token_is_active_for_user(
                    token, 
                    user_id=user_id,
                    expires=get_epoch_now()
                ):
            raise jwt.exceptions.ExpiredSignatureError()
        elif scenario.startswith("refresh") and \
                not (x := c.db.check_if_refresh_token_is_active_for_user(
                    token, 
                    user_id=user_id,
                    expires=get_epoch_now())
                ):
            raise jwt.exceptions.ExpiredSignatureError()
        return payload  
    except jwt.exceptions.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

def get_epoch_now(**timedeltas) -> int:
    return int((datetime.now() + timedelta(**timedeltas)).timestamp())

def generate_guid() -> str:
    return str(uuid.uuid4())

def generate_random_password() -> str:
    return "".join(SystemRandom().choice(ascii_letters + ascii_uppercase + ascii_lowercase) for _ in range(10))

def check_if_user_can_login(user_id:int, controller:Controller=c) -> None:
    expires = get_epoch_now()
    # check if account is blocked due to maximum invalid attempts
    
    if ( controller.db.get_failed_login_attempts(user_id, expires) > controller.MAX_LOGIN_ATTEMPTS ) :
        raise UserIsBlocked()

