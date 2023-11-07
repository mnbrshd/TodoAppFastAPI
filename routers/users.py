from fastapi import APIRouter, Depends, Request, status, Form
from fastapi.responses import HTMLResponse, RedirectResponse
import models
from database import engine
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from typing import Annotated
from pydantic import BaseModel
from auth import get_current_user, get_password_hash, verify_password, get_db
from fastapi.templating import Jinja2Templates

router = APIRouter(
    prefix='/users',
    tags=['users'],
    responses={404: {"description": "Not Found"}}
)

models.Base.metadata.create_all(bind=engine)
templates = Jinja2Templates(directory="templates")

class UserVerification(BaseModel):
    username: str
    password: str
    new_password: str

@router.get("/edit-password", response_class=HTMLResponse)
async def edit_user_view(request: Request):
    user = await get_current_user(request)

    if user is None:
        return RedirectResponse(url="/auth", status_code=status.HTTP_302_FOUND)
    
    
    return templates.TemplateResponse("edit-user-password.html", {"request": request, "user": user})


@router.post('/edit-password', response_class=HTMLResponse)
async def user_password_change(request: Request, username: str = Form(...), password: str = Form(...), password2: str = Form(...), db: Session = Depends(get_db)):
    user = await get_current_user(request)

    if user is None:
        return RedirectResponse(url="/auth", status_code=status.HTTP_302_FOUND)
    
    user_model = db.query(models.Users).filter(models.Users.username == username).first()

    msg = "Invalid username or password"

    if user_model is not None:
        if username == user_model.username and verify_password(password, user_model.hashed_password):
            user_model.hashed_password = get_password_hash(password2)
            db.add(user_model)
            db.commit()
            msg = "Password updated"

    return templates.TemplateResponse("edit-user-password.html", {"request": request, "msg": msg, "user": user})

