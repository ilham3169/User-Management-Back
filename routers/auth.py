from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy.orm import Session
from typing import Annotated

from security import hash_password, verify_password
from models import Login, Role
from schemas import LoginRequest, LoginCreate


from database import SessionLocal

router = APIRouter(
    prefix="/auth",
    tags=["auth"]
)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

db_dependency = Annotated[Session, Depends(get_db)]

@router.post("/login", status_code=status.HTTP_200_OK)
async def check_user(credentials: LoginRequest, db: db_dependency):
    user = db.query(Login).filter(Login.username == credentials.username).first()

    if(not user or not verify_password(credentials.password_hash, user.password_hash)): raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")
    if(not user.is_active): raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is inactive")
    return {"message": "Successful login", "user_id": user.id, "username": user.username, "role_id": user.role_id}


@router.post("/register", status_code=status.HTTP_200_OK)
async def register_user(credentials: LoginCreate, db: db_dependency):
    
    user = db.query(Login).filter(Login.username == credentials.username).first()
    if(user): return {"message" : "This username exists"}

    role = db.query(Role).filter(credentials.role_id == Role.id).first()
    if(not role): return {"message" : "No role with this ID"}

    user_data = credentials.dict()
    user_data["password_hash"] = hash_password(user_data["password_hash"])

    new_user = Login(**user_data)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"message" : "Succesful", "New User" : new_user}




