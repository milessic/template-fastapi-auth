from fastapi import  FastAPI, status, Request, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from utils.auth.utils import verify_access_token
from routers import auth
from utils.controller import Controller


c = Controller()

print(c.SWAGGER_URL, c.REDOC_URL, c.OPENAPI_URL)
app = FastAPI(
        name="main",
        docs_url=c.SWAGGER_URL,
        redoc_url=c.REDOC_URL,
        openapi_url=c.OPENAPI_URL
        )




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
    if access_token is not None: 
        try:
            verify_access_token(access_token)
            return templates.TemplateResponse("index.html", {"request": request})
        except HTTPException:
            pass
    return templates.TemplateResponse("login.html", {"request": request})


@app.get("/register", response_class=HTMLResponse, include_in_schema=False)
async def get_register_page(request: Request):
    if False and request.__dict__.get("_cookies").get("access_token"):
        response = RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
        response.request = request
        return response
    return templates.TemplateResponse("register.html", {"request": request})


@app.get("/forgot-password", response_class=HTMLResponse, include_in_schema=False)
async def get_forgot_password_page(request:Request):
    return templates.TemplateResponse("forgotpassword.html",{"request":request})

app.mount("/static", StaticFiles(directory="ui"), name="static")

app.include_router(auth.router, prefix="/api/auth", tags=["Auth"])

