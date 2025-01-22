from typing import Annotated
import jwt
from fastapi.responses import RedirectResponse

from fastapi import Depends, FastAPI, HTTPException, status, Request, Form, Response, APIRouter
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from utils.auth.models import RegisterModel, LoginModel
from utils.auth.utils import *
from utils.auth.validators import *
from utils.controller import Controller

c = Controller()

router = APIRouter()



@router.post("/register")
async def register(register_model: RegisterModel):
    data_as_dict = json_to_dict(register_model)
    username = data_as_dict.get("username")
    password = data_as_dict.get("password")
    email = data_as_dict.get("email")
    errors = []
    # username
    if (err := validate_username(username, c.db)):
        errors.append(generate_username_response(err))
    # email
    if not len(errors) and (err := validate_email(email, c.db)):
        errors.append(generate_email_response(err))
    # password
    if (err := validate_password(password)):
        errors.append(generate_password_response(err))
    if len(errors):
        raise HTTPException(status_code=400, detail=errors)
    # hash password
    data_as_dict["password"] = hash_password(password)
    c.db.create_user(data_as_dict)

    return {"message": "registered"}

@router.get("/api/user/logout")
async def logout(response: Response):
    response = RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(key="access_token")
    return response

@router.post("/api/token")
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    # validate inputs
    errors = []
    user_data = c.db.get_user_data(form_data.username)
    if isinstance(user_data, bool):
        raise HTTPException(400, "Login or email doesn't exist")
    if not unhash_password(form_data.password, user_data[2]):
        raise HTTPException(400, "Password is not correct!")

    # generate bearer
    access_token = generate_access_token(form_data.username, c.SECRET_KEY, algorithm=c.ALGORITHM, expires_delta=timedelta(minutes=c.ACCESS_TOKEN_EXPIRES_MINUTES))
    return {"access_token": access_token, "token_type": "bearer"}


async def login_user():
    pass

@router.get("/api/me")
async def get_my_details(token:str= Depends(c.oauth2_scheme)):
    credentials_exception = HTTPException(
            status_code=401,
            detail="Could not validate credentials"
            )
    try:
        payload = decode_access_token(token, SECRET_KEY, ALGORITHM)
        login = payload.get("sub")
        if login is None:
            raise credentials_exception
    except Exception as e:
        raise credentials_exception
    user = c.db.get_user_data(login)
    if not(user):
        raise credentials_exception
    return {"username": user[0], "email": user[1]}


@router.post("/login/submit", include_in_schema=False)
async def submit_login_form(
        response: Response,
        username: str = Form(),
        password: str = Form(),
        ):
    login_form = OAuth2PasswordRequestForm(username=username, password=password)
    login_resp = await login(login_form)
    access_token = login_resp.get("access_token")
    if access_token:
        response = RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER, )
        response.set_cookie(key="access_token", value=access_token, httponly=True, max_age=c.ACCESS_TOKEN_EXPIRES_MINUTES * 60)
    else:
        return {"msg", "ERROR"}
    return response
    



@router.post("/register/submit",include_in_schema=False)
async def submit_register_form(
        username: str = Form(), 
        email: str= Form(), 
        password: str = Form(),
        ):
    register_model = RegisterModel(**{"username": username, "email": email, "password":password})
    try:
        register_response = await register(register_model)
    except Exception as e:
        print(str(type(e)) + str(e))
        errors = ""
        if 'Username' in str(e):
            errors += 'username=alreadytaken&'
        if 'Email' in str(e):
            errors += 'email=alreadytaken&'
        if 'Password' in str(e):
            errors += 'password=invalid'
        if errors:
            errors = errors.removesuffix("&")
            return RedirectResponse(f"/register?status=failure&{errors}", status_code=status.HTTP_303_SEE_OTHER)
        return RedirectResponse(f"/register?status=unknownfailure", status_code=status.HTTP_303_SEE_OTHER)
    if register_response.get("message") == "registered":
        return RedirectResponse(f"/?status=success&username={username}", status_code=status.HTTP_303_SEE_OTHER)

@router.get("/logout", include_in_schema=False)
async def ui_logout(response:Response):
    response = RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(key="access_token")
    return response

