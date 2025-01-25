from typing import Annotated
import jwt

from fastapi import Depends, FastAPI, HTTPException, status, Request, Form, Response
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from routers import auth



app = FastAPI(name="main")


templates = Jinja2Templates(directory="ui")



async def login_user():
    pass

@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def get_homepage(request: Request):
    # TODO handle logged in scenario
    """request": request"
    if user is already authernticated, chats should be served
    if user is not, login page
    """
    access_token = request.cookies.get("access_token")
    if access_token:
        return templates.TemplateResponse("index.html", {"request": request})
    return templates.TemplateResponse("login.html", {"request": request})


@app.get("/register", response_class=HTMLResponse, include_in_schema=False)
async def get_register_page(request: Request):
    if request.__dict__.get("_cookies").get("access_token"):
        response = RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
        response.request = request
        return response
    return templates.TemplateResponse("register.html", {"request": request})




app.mount("/static", StaticFiles(directory="ui"), name="static")

app.include_router(auth.router, prefix="/api/auth", tags=["Auth"])
