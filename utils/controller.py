from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from utils.db.db_clients import DbClient
import os
from dotenv import load_dotenv, dotenv_values

class Controller:
    def __init__(self):
        self.env_file_path = os.path.dirname(os.path.abspath(os.path.dirname(__file__)))
        self.config = dotenv_values(".env")

        self.SECRET_KEY = None
        self.ALGORITHM = None
        self.ACCESS_TOKEN_EXPIRES_MINUTES = None
        self.REFRESH_TOKEN_EXPIRES_MINUTES = None

        self.load_env_variables()
        self.oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/auth/token")
        self.db = DbClient("NameYourDb")

    def load_env_variables(self):
        try:
            self.SECRET_KEY = self.config.get("SECRET_KEY")# TODO load from .env
            self.ALGORITHM = self.config.get("ALGORITHM")
            self.ACCESS_TOKEN_EXPIRES_MINUTES = int(float(self.config.get("ACCESS_TOKEN_EXPIRES_MINUTES")))
            self.REFRESH_TOKEN_EXPIRES_MINUTES = int(float(self.config.get("REFRESH_TOKEN_EXPIRES_MINUTES")))
        except:
            raise AttributeError(".env file not found or doens't have proper key=values")

        return
        #
        self.SECRET_KEY = "qwerty" # TODO load from .env
        self.ALGORITHM = "HS256"
        self.ACCESS_TOKEN_EXPIRES_MINUTES = 2
        self.REFRESH_TOKEN_EXPIRES_MINUTES = 1200
