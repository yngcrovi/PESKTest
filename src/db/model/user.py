from db.model.base import Base
from sqlalchemy import Column, String, Text, DateTime, func
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import BYTEA, UUID
import uuid

class UserModel(Base):
    __tablename__ = "user"
    
    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default="gen_random_uuid()"
    )
    username = Column(String(100), unique=True, nullable=True)
    password = Column(BYTEA, nullable=False)
    salt = Column(BYTEA, nullable=False)
    create_dt = Column(DateTime, server_default=func.now(), nullable=False)
    
    def __repr__(self):
        return f"<User(id={self.id}, username={self.username})>"