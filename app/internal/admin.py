import secrets
from fastapi import APIRouter, Body, Depends
from pydantic import BaseModel
from typing_extensions import Annotated
from ..dependencies import db
from app.routers.user import User, Message, get_password_hash, admin_required

router = APIRouter(prefix='/admin',
                   tags=['admin'],
                   dependencies=[Depends(admin_required)],
                   responses={404: {'description': 'Not found'}})


class ResetPassword(BaseModel):
    username: str
    password: str = secrets.token_urlsafe()


@router.post("/",
             response_model=User)
async def create_user(user: Annotated[User, Body()]):
    result = await db.user.insert_one(
        user.model_dump(by_alias=True, exclude=['id', 'password'])
    )
    created_user = await db.user.find_one(
        {"_id": result.inserted_id}
    )
    return created_user


@router.put("/reset",
            response_model=Message)
async def reset_user_password(req: Annotated[ResetPassword, Body()]):
    result = await db.user.update_one(
        {'username': req.username},
        {'$set': {'password': get_password_hash(req.password)}}
    )
    if result.modified_count == 1:
        return {'status': 'success', 'message': 'Password is reset'}
    else:
        return {'status': 'error', 'message': 'User not found'}
