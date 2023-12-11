from fastapi import APIRouter, Body, Depends
from pydantic import BaseModel, Field, conlist
from datetime import datetime
from typing_extensions import Annotated
from bson import ObjectId
from ..dependencies import db, PyObjectId
from .user import get_current_user
from .note import Note
from . import tag, follow
from .model import Fund

router = APIRouter(prefix='/fund',
                   tags=['fund'],
                   dependencies=[Depends(get_current_user)],
                   responses={404: {'description': 'Not found'}})

router.include_router(tag.router)
router.include_router(follow.router)

COUNT_FUND_BY_ASSET_CLASS = [
    {
        '$group': {
            '_id': '$assetClasses', 
            'count': {
                '$sum': 1
            }
        }
    }, {
        '$unwind': {
            'path': '$_id'
        }
    }, {
        '$group': {
            '_id': '$_id', 
            'count': {
                '$sum': '$count'
            }
        }
    }, {
        '$sort': {
            'count': -1
        }
    }
]



class AssetClassCount(BaseModel):
    assetClasses: str = Field(alias="_id", default=None)
    count: int

@router.post("/",
             response_model=Fund)
async def create_new_fund(req: Annotated[Fund, Body()]):
    result = await db.fund.insert_one(
        req.model_dump(by_alias=True, exclude=['id'])
    )
    created_fund = await db.fund.find_one(
        {"_id": result.inserted_id}
    )
    return created_fund


@router.get("/", response_model=list[Fund])
async def get_all_funds():
    return await db.fund.find({}).collation({'locale': 'en'}).sort({'name': 1}).to_list(1000)


@router.get("/assetClass", response_model=list[AssetClassCount])
async def get_asset_classes():
    return await db.fund.aggregate(COUNT_FUND_BY_ASSET_CLASS).to_list(1000)


@router.get("/assetClass/{assetClass}", response_model=list[Fund])
async def get_fund_by_asset_class(assetClass: str):
    return await db.fund.find({'assetClasses': assetClass}).sort({'name': 1}).to_list(1000)


@router.get("/{id}", response_model=Fund)
async def get_fund_details(id: str):
    return await db.fund.find_one({'_id': ObjectId(id)})


@router.get("/{id}/note", response_model=list[Note])
async def get_fund_notes(id: str):
    """Including draft"""
    return await db.note.find({'fundId': ObjectId(id)}).sort({'modifiedDate': -1}).to_list(1000)
