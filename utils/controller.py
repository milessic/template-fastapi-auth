from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from utils.db.db_clients import DbClient

class Controller:
    def __init__(self):
        self.oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/auth/token")
        self.db = DbClient("NameYourDb")
        self.SECRET_KEY = "qwerty" # TODO load from .env
        self.ALGORITHM = "HS256"
        self.ACCESS_TOKEN_EXPIRES_MINUTES = 600

