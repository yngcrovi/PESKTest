from pydantic_settings import BaseSettings, SettingsConfigDict


class Env(BaseSettings):
    # LOGIN_URL: str
    # REDIS_PASSWORD: str
    # REDIS_PORT: int
    # REDIS_PORT_TEST: int
    # HOST_EQ: str
    SECRET_KEY: str
    TOKEN_ALGORITHM: str
    ACCESS_TOKEN_EXP_SECOND: int
    REFRESH_TOKEN_EXP_SECOND: int
    # NUMBER_OF_ITERATIONS: int
    # PASSWORD_ALGORITHM: str
    # NODE_ENV: str

    model_config = SettingsConfigDict(env_file="../.env", extra='ignore')

env = Env()