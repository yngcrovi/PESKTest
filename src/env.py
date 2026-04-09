from pydantic_settings import BaseSettings, SettingsConfigDict


class Env(BaseSettings):
    SECRET_KEY: str
    TOKEN_ALGORITHM: str
    ACCESS_TOKEN_EXP_SECOND: int
    SESSION_EXP: int
    NUMBER_OF_ITERATIONS: int
    PASSWORD_ALGORITHM: str
    REDIS_HOST: str
    REDIS_PORT: int

    model_config = SettingsConfigDict(env_file="../.env", extra='ignore')

env = Env()