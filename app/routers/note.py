from datetime import datetime, timezone
from typing_extensions import Annotated
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from bson import ObjectId
from ..dependencies import db, PyObjectId
from .user import User, get_current_user

router = APIRouter(prefix='/note',
                   tags=['note'],
                   dependencies=[Depends(get_current_user)],
                   responses={404: {'description': 'Not found'}})

class Note(BaseModel):
    id: PyObjectId = Field(alias="_id", default=None)
    authorId: PyObjectId
    authorName: str
    fundId: PyObjectId
    fundName: str
    modifiedDate: datetime
    content: str
    published: bool


class UpdateNote(BaseModel):
    content: str
    published: bool


@router.get("/", response_model=list[Note])
async def get_published_notes(skip: int = 0, limit: int = 1):
    return await db.note.find({'published': True}).sort({'modifiedDate': -1}).skip(skip).limit(limit).to_list(limit)


@router.get("/{id}", response_model=Note)
async def get_note(id):
    return await db.note.find_one({'_id': ObjectId(id)})


@router.post("/{fund_id}", response_model=Note)
async def post_new_note(
    fund_id: str,
    current_user: Annotated[User, Depends(get_current_user)]
):
    print('*******')
    fund = await db.fund.find_one({'_id': ObjectId(fund_id)})
    print('*******', fund)
    result = await db.note.insert_one({
        'authorId': current_user.id,
        'authorName': current_user.first_name + ' ' + current_user.last_name,
        'fundId': fund['_id'],
        'fundName': fund['name'],
        'modifiedDate': datetime.now(tz=timezone.utc),
        'content': '',
        'published': False
    })
    created_note = await db.note.find_one(
        {"_id": result.inserted_id}
    )
    return created_note


@router.put("/{id}", response_model=Note)
async def save_note(id: str, update: UpdateNote):
    # TODO: Check user is the original author
    await db.note.update_one({'_id': ObjectId(id)}, {'$set': {
        'content': update.content,
        'published': update.published,
        'modifiedDate': datetime.now(tz=timezone.utc)
    }})
    updated_note = await db.note.find_one(
        {"_id": ObjectId(id)}
    )
    return updated_note