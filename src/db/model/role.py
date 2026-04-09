from db.model.base import Base
from sqlalchemy import Column, String, Integer
from sqlalchemy.orm import relationship

class RoleModel(Base):
    __tablename__ = "role"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(150), nullable=True)
    
    
    def __repr__(self):
        return f"<Role(id={self.id}, name={self.name})>"
    
