from typing_extensions import Annotated
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from ..dependencies import db, PyObjectId
from .user import User, get_current_user

router = APIRouter(prefix='/tag',
                   tags=['tag'],
                   dependencies=[Depends(get_current_user)],
                   responses={404: {'description': 'Not found'}})

def find_descendants(ancestor):
    return [
    {
        '$match': {
            '_id': ancestor
        }
    }, {
        '$graphLookup': {
            'from': 'tag', 
            'startWith': '$children', 
            'connectFromField': 'children', 
            'connectToField': '_id', 
            'depthField': 'depth', 
            'as': 'descendants'
        }
    }
]

def find_ancestors(descendant):
    return [
    {
        '$match': {
            '_id': descendant
        }
    }, {
        '$graphLookup': {
            'from': 'tag', 
            'startWith': '$_id', 
            'connectFromField': '_id', 
            'connectToField': 'children', 
            'depthField': 'depth', 
            'as': 'ancestors'
        }
    }
]

class Tag(BaseModel):
    id: str = Field(alias="_id")
    children: list[str]
    depth: int


@router.get("/", response_model=list[str])
async def get_all_tags():
    tags = await db.tag.find({}, {'_id': 1}).collation({'locale': 'en'}).sort({'_id': 1}).to_list(1000)
    return map(lambda t: t['_id'], tags)

@router.get("/{tag}/ancestors", response_model=list[str])
async def get_tag_ancestors(tag):
    """Used by Breadcrumbs"""
    tags = await db.tag.aggregate(find_ancestors(tag)).to_list(1000)
    print('tags', tags)
    sorted_tags = sorted(tags[0]['ancestors'], key=lambda t: t['depth'], reverse=True)
    return list(map(lambda s: s['_id'], sorted_tags))

@router.get("/{tag}/descendants", response_model=list[Tag])
async def get_tag_descendants(tag):
    """Used by TreeView"""
    tags = await db.tag.aggregate(find_descendants(tag)).to_list(1000)
    return sorted(tags[0]['descendants'], key=lambda t: t['depth'])
