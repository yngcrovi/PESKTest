from fastapi import APIRouter, Request, Depends, Cookie
from fastapi.responses import JSONResponse
from db.service import RoleService, UserRoleService
from pydantic import BaseModel 
from auth.token import TokenManager

route = APIRouter(
    prefix='/role',
    tags=['Role'],
)

class RolesResponse(BaseModel):
    id: int
    name: str

# Получение всех ролей
@route.get("/get", response_model=list[RolesResponse])
async def get_roles(request: Request, role_service: RoleService = Depends(RoleService), access_token: str = Cookie(default=None, alias="access_token")):
    token: TokenManager = request.app.state.token_manager
    await token.decode_and_verify_token(access_token, request)
    return await role_service.get_roles()

# Добавить роль пользователя по id
@route.post("/add")
async def add_roles(
    request: Request, role_id: int, role_service: RoleService = Depends(RoleService), user_role_service: UserRoleService = Depends(UserRoleService), 
    access_token: str = Cookie(default=None, alias="access_token")
) -> dict:
    token: TokenManager = request.app.state.token_manager
    payload = await token.decode_and_verify_token(access_token, request)
    if not (await role_service.check_role(role_id)):
        return JSONResponse(content={"error": "current role not exist"}, status_code=404)
    await user_role_service.insert_role(payload["sub"], role_id)
    return JSONResponse(content={"success": "The role has been added to the user"})

# Удалить роль пользователя по id
@route.post("/revoke")
async def revoke_role(
    request: Request, role_id: int, role_service: RoleService = Depends(RoleService), user_role_service: UserRoleService = Depends(UserRoleService),
    access_token: str = Cookie(default=None, alias="access_token")
) -> dict: 
    token: TokenManager = request.app.state.token_manager
    payload = await token.decode_and_verify_token(access_token, request)
    if not (await role_service.check_role(role_id)):
        return JSONResponse(content={"error": "current role not exist"}, status_code=404)
    await user_role_service.revoke_role(payload["sub"], role_id)
    return JSONResponse(content={"success": "The role has been revoke to the user"})

# Получить роли конкретного пользователя
@route.post("/get_user")
async def revoke_role(
    request: Request, user_role_service: UserRoleService = Depends(UserRoleService),
    access_token: str = Cookie(default=None, alias="access_token")
) -> list[str]: 
    token: TokenManager = request.app.state.token_manager
    payload = await token.decode_and_verify_token(access_token, request)
    return await user_role_service.get_roles_user(payload["sub"])