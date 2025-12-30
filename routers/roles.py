from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy.orm import Session
from typing import Annotated

from models import Login, Role
from schemas import LoginRequest, LoginCreate


from database import SessionLocal

router = APIRouter(
    prefix="/roles",
    tags=["roles"]
)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

db_dependency = Annotated[Session, Depends(get_db)]

@router.get("/all-roles", status_code=status.HTTP_200_OK)
async def get_all_roles(db: db_dependency):
    roles = db.query(Role).all()
    return roles

@router.get("/role", status_code=status.HTTP_200_OK)
async def get_role(id: int, db: db_dependency):
    role = db.query(Role).filter(Role.id == id).first()
    if(not role): raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found")
    return role
