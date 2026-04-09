from fastapi import APIRouter, Request, Depends, Cookie
from fastapi.responses import JSONResponse
from db.service import UserRoleService
from auth.token import TokenManager
from redis import Redis

route = APIRouter(
    prefix='/content',
    tags=['Content'],
)

# Получить чёрный список токенов(только для права "Админ")
@route.get("/blacklist")
async def get_admin_data(
    request: Request, user_role_service: UserRoleService = Depends(UserRoleService), access_token: str = Cookie(default=None, alias="access_token")
) -> list[dict] | dict:
    token: TokenManager = request.app.state.token_manager
    redis: Redis = request.app.state.redis
    payload = await token.decode_and_verify_token(access_token, request)
    if not (await user_role_service.check_role_admin(payload["sub"])):
        return JSONResponse(content={"error": "You do not have admin rights to access the resource"}, status_code=403)
    blacklist_keys: list[str] = await redis.keys("blacklist:*")
    data = []
    for key in blacklist_keys:
        info = await redis.get(key)
        data.append({
            "token_id": key.replace("blacklist:", ""),
            "info": info
        })
    return data

# Получить публичную информацию(для всех ролей)
@route.get("/")
async def get_public_data(
    request: Request, user_role_service: UserRoleService = Depends(UserRoleService), access_token: str = Cookie(default=None, alias="access_token")
) -> JSONResponse:
    token: TokenManager = request.app.state.token_manager
    payload = await token.decode_and_verify_token(access_token, request)
    if not await user_role_service.check_any_role(payload["sub"]):
        return JSONResponse(content={"error": "You do not have any rights to access the resource"}, status_code=403)
    return JSONResponse(content={"success": "You get public data!"})