from sqlalchemy import select, insert
from db.model import UserModel
from db.config.engine import EngineDB
from uuid import UUID

class UserService:
    
    def __init__(self):
        self.session = EngineDB().get_engine()
        self.table = UserModel

    async def exist_user(self, username: str) -> bool:
        async with self.session as s:
            query = select(self.table).where(self.table.username == username)
            result = await s.execute(query)
            user = result.scalar_one_or_none() 
            return user is not None

    async def create_user(self, data: dict) -> UUID:
        async with self.session as s:
            stmt = insert(self.table).values(**data).returning(self.table.id)
            result = await s.execute(stmt)
            await s.commit()
            user_id = result.scalar_one()     
            return user_id
        
    async def get_password_data(self, username: str) -> dict:
        async with self.session as s:
            query = select(self.table.password, self.table.salt).where(self.table.username == username)
            result = await s.execute(query)
            return result.mappings().all()[0]
        
    async def get_user_id(self, username: str) -> dict:
        async with self.session as s:
            query = select(self.table.id).where(self.table.username == username)
            result = await s.execute(query)
            return result.scalar_one()