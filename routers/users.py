import bcrypt
from fastapi import APIRouter,Depends,HTTPException, Path
from pydantic import BaseModel, Field
from models import Users
from database import SessionLocal
from typing import Annotated
from sqlalchemy.orm import Session
from starlette import status
from .auth import get_current_user
from passlib.context import CryptContext

router=APIRouter(
    prefix='/user',
    tags=['user']
)



def get_db():
    db=SessionLocal()
    try:
        yield db
    finally:
        db.close()

db_dependency = Annotated[Session, Depends(get_db) ]
user_dependency = Annotated[dict,Depends(get_current_user)]

bcypt_context=CryptContext(schemes=['bcrypt'],deprecated='auto')

class PasswordVerification(BaseModel):
    prev_password: str
    new_password: str=Field(min_length=5)

@router.post("/",status_code=status.HTTP_200_OK)
async def get_user(user:user_dependency,db:db_dependency):
    if user is None:
        raise HTTPException(status_code=401,detail="auth failed")
    us_id=user.get('user_id')
    return db.query(Users).filter(Users.id==us_id).first()

@router.put("/PasswordChange",status_code=status.HTTP_204_NO_CONTENT)
async def get_user(user:user_dependency,db:db_dependency,pass_ver:PasswordVerification):
    if user is None:
        raise HTTPException(status_code=401,detail="auth failed")
    us_id=user.get('user_id')
    user_model=db.query(Users).filter(Users.id==us_id).first()
    if not bcypt_context.verify(pass_ver.prev_password,user_model.hashed_password):
        raise HTTPException(status_code=401, detail="Password is wrong")
    if bcypt_context.verify(pass_ver.new_password,user_model.hashed_password):
        raise HTTPException(status_code=400, detail="New password cannot be the same as the old one")
    if user_model is None:
        raise HTTPException(status_code=404,detail="User not found")
    user_model.hashed_password=bcypt_context.hash(pass_ver.new_password)
    db.add(user_model)
    db.commit()