from sqlalchemy import select, insert, exists, delete, and_
from fastapi import status, HTTPException
from db.model import UserRoleModel, RoleModel
from db.config.engine import EngineDB
from uuid import UUID


class UserRoleService:
    
    def __init__(self):
        self.session = EngineDB().get_engine()
        self.table = UserRoleModel

    async def check_role_user(self, user_id: UUID, role_id: int) -> bool:
        async with self.session as s:
            stmt = select(exists().where(and_(self.table.user_id == user_id, self.table.role_id == role_id)))
            result = await s.execute(stmt)
            return result.scalar()


    async def insert_role(self, user_id: UUID, role_id: int) -> None:
        if await self.check_role_user(user_id, role_id):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="This user already has this role"
            )
        async with self.session as s:
            stmt = insert(self.table).values({"user_id": user_id, "role_id": role_id})
            await s.execute(stmt)
            await s.commit()

    async def revoke_role(self, user_id: UUID, role_id: int) -> None:
        async with self.session as s:
            stmt = delete(self.table).where(and_(self.table.user_id == user_id, self.table.role_id == role_id))
            await s.execute(stmt)
            await s.commit()

    async def get_roles_user(self, user_id: UUID) -> list:
        async with self.session as s:
            query = (
                select(RoleModel.name)
                .join(self.table, self.table.role_id == RoleModel.id)
                .where(self.table.user_id == user_id)
            )
            result = await s.execute(query)
            return result.scalars().all()
        
    async def check_role_admin(self, user_id: UUID):
        async with self.session as s:
            query = (
                select(self.table)
                .join(RoleModel, self.table.role_id == RoleModel.id)
                .where(and_(self.table.user_id == user_id, RoleModel.name == "Админ"))
            )
            result = await s.execute(query)
            return result.scalar()
        
    async def check_any_role(self, user_id: UUID):
        async with self.session as s:
            query = (
                select(self.table)
                .join(RoleModel, self.table.role_id == RoleModel.id)
                .where(self.table.user_id == user_id)
            )
            result = await s.execute(query)
            return result.scalar()
    
    