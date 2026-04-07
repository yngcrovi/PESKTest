from fastapi import Cookie, Header
from jose import jwt, JWTError
from time import time
from env import env
from fastapi import HTTPException, status

class Token:

    def __init__(self) -> None:
        self.key = env.SECRET_KEY
        self.algorithm = env.TOKEN_ALGORITHM
        self.access_exp = env.ACCESS_TOKEN_EXP_SECOND
        self.refresh_exp = env.REFRESH_TOKEN_EXP_SECOND

    #TODO: Написать корректный тип времени токена
    def create_token(self, payload: dict) -> str:
        token = jwt.encode(payload, self.key, algorithm=self.algorithm)
        return token

    def create_access_token(self, payload: dict) -> str:
        payload["exp"]  = int(time()) + self.access_exp
        token = self.create_token(payload)
        return token

    def create_refresh_token(self, payload: dict) -> str:
        payload["exp"] = int(time()) + self.refresh_exp
        token = self.create_token(payload)
        return token

    def decode_token(self, token: str | None, error_detail: str) -> dict:
        try:
            payload = jwt.decode(token, self.key, algorithms=[self.algorithm])
            return payload
        except (JWTError, AttributeError) as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=error_detail,
            )

    def decode_access_token(self, access_token: str = Cookie(default=None)):
        return self.decode_token(access_token, "Invalid access token")

    def decode_refresh_token(self, token: str = Header(..., alias="Authorization")):
        return self.decode_token(token.replace('Bearer', '').strip(), "Invalid refresh token")
    
token = Token()