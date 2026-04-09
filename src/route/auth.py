from fastapi import APIRouter, Request, Depends, Cookie
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from auth.token import TokenManager
import os
from db.service import UserService
from auth.password import Password
from env import env
from uuid import UUID

class LoginModel(BaseModel):
    username: str
    password: str

route = APIRouter(
    prefix='/auth',
    tags=['Auth'],
)

# Регистрация пользователя
@route.post('/registration')
async def registration(
        request: Request, user_data: LoginModel, user_service: UserService = Depends(UserService), password_service: Password = Depends(Password)
    ) -> dict:
    if await user_service.exist_user(user_data.username):
        return JSONResponse({"error": "This user is already exists"}, status_code=409)
    else: 
        token: TokenManager = request.app.state.token_manager
        data = {**user_data.model_dump(), "salt": os.urandom(32)}
        data["password"] = password_service.make_hash_password(data["password"], data["salt"])
        user_id = await user_service.create_user(data)
        access_token = await token.create_access_token(user_id, request)
        response = JSONResponse(content={"success": f"user {user_data.username} is registered"})
        response.set_cookie(
            key="access_token",
            value=access_token["token"],  
            httponly=True,                
            expires=env.ACCESS_TOKEN_EXP_SECOND,                
            path="/",                     
        )
        return response

# Вход пользователя
@route.post('/login')
async def login(
    request: Request, user_data: LoginModel, user_service: UserService = Depends(UserService), access_token: str = Cookie(default=None, alias="access_token"), 
    password_service: Password = Depends(Password)
) -> dict:
    token: TokenManager = request.app.state.token_manager
    if not (await user_service.exist_user(user_data.username)):
        return JSONResponse({"error": f"The user {user_data.username} is not registered"}, status_code=409)
    password_salt: dict = await user_service.get_password_data(user_data.username)
    if not(password_service.compare_password(password_salt["password"], password_salt["salt"], user_data.password)):
        return JSONResponse({"error": "Incorrect user password"}, status_code=401)
    user_id: UUID = await user_service.get_user_id(user_data.username)
    await token.delete_user_session(user_id)
    access_token = await token.create_access_token(user_id, request)
    response = JSONResponse(content={"success": f"user {user_data.username} login"})
    response.set_cookie(
        key="access_token",
        value=access_token["token"],  
        httponly=True,                
        expires=env.ACCESS_TOKEN_EXP_SECOND,                
        path="/",                     
    )
    return response

# Выход пользователя
@route.post('/logout')
async def logout(
    request: Request
) -> dict:
    response = JSONResponse(content={"success": "user logout"})
    response.delete_cookie("access_token", path="/")
    return response

