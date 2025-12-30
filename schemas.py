from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime

class LoginRequest(BaseModel):
    username: str
    password_hash: str

class LoginCreate(BaseModel):
    username: str
    password_hash: str = Field(..., max_length=72) 
    role_id: int


class RoleBase(BaseModel):
    name: str
    description: Optional[str] = None

