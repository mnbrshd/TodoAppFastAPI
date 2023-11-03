from fastapi import APIRouter, Depends, HTTPException, status, Path
from models import Users
from database import SessionLocal
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from typing import Annotated
from pydantic import BaseModel, Field
from .auth import get_current_user

router = APIRouter(
    prefix='/user',
    tags=['user']
)

bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

db_dependency = Annotated[Session, Depends(get_db)]
user_dependecy = Annotated[dict, Depends(get_current_user)]

class UserVerification(BaseModel):
    password: str
    new_password: str = Field(min_length=6)


# @router.get('/', status_code=status.HTTP_200_OK)
# async def read_all_users(user: user_dependecy, db: db_dependency):
#     if user is None:
#         raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Authentication Failed')
    
#     return db.query(Users).all()

@router.get('/', status_code=status.HTTP_200_OK)
async def get_user(user: user_dependecy, db: db_dependency):
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Authentication Failed')
    return db.query(Users).filter(Users.id == user.get('id')).first()

@router.put('/password', status_code=status.HTTP_204_NO_CONTENT)
async def change_password(user: user_dependecy, db: db_dependency, user_verification: UserVerification):
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Authentication Failed')
    
    user_model = db.query(Users).filter(Users.id == user.get('id')).first()

    user_model.hashed_password = bcrypt_context.hash(user_verification.password)

    db.add(user_model)
    db.commit()

@router.put('/phone_number/{phone_number}', status_code=status.HTTP_204_NO_CONTENT)
async def update_phone_number(user: user_dependecy, db: db_dependency, phone_number: str):
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Authentication Failed')

    user_model = db.query(Users).filter(Users.id == user.get('id')).first()

    user_model.phone_number = phone_number

    db.add(user_model)
    db.commit()