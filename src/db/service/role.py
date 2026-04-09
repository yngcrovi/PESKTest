from sqlalchemy import select, insert
from db.model import RoleModel
from db.config.engine import EngineDB
from uuid import UUID

class RoleService:
    
    def __init__(self):
        self.session = EngineDB().get_engine()
        self.table = RoleModel

    async def get_roles(self) -> list[int]:
        async with self.session as s:
            query = select(self.table)
            result = await s.execute(query)
            return result.scalars().all()
        
    async def check_role(self, role_id: int) -> bool:
        async with self.session as s:
            return await s.get(self.table, role_id)