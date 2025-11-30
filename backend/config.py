import os
from decouple import config

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = config("SECRET_KEY")
    SQLALCHEMY_TRACK_MODIFICATIONS = config("SQLALCHEMY_TRACK_MODIFICATIONS", cast=bool)


class devconfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = f"sqlite:///" + os.path.join(
        BASE_DIR, "dev.db"
    )  ## MULTItool./backend/dev.db


class testconfig(Config):
    SQLALCHEMY_DATABASE_URI = f"sqlite:///" + os.path.join(
        BASE_DIR, "test.db"
    )  ## MULTItool./backend/test.db
    TESTING = True
    SQLALCHEMY_ECHO = False


class prodconfig(Config):
    # SQLALCHEMY_DATABASE_URI = f"porsgre:///iP:port:user"config('datapass')  ## MULTItool./backend/dev.db
    pass
