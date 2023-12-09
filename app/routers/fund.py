from fastapi import APIRouter, Body, Depends
from pydantic import BaseModel, Field, conlist
from datetime import datetime
from typing_extensions import Annotated
from bson import ObjectId
from ..dependencies import db, PyObjectId
from .user import get_current_user
from .note import Note

router = APIRouter(prefix='/fund',
                   tags=['fund'],
                   dependencies=[Depends(get_current_user)],
                   responses={404: {'description': 'Not found'}})


class Fund(BaseModel):
    id: PyObjectId = Field(alias="_id", default=None)
    name: str = Field(min_length=1)
    firm: str = Field(min_length=1)
    assetClasses: conlist(str, min_length=1)
    launchDate: datetime | None = None


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


@router.get("/assetClass", response_model=list[str])
async def get_asset_classes():
    return await db.fund.distinct('assetClasses')


@router.get("/assetClass/{assetClass}", response_model=list[Fund])
async def get_fund_by_asset_class(assetClass: str):
    print('aaaa', assetClass)
    return await db.fund.find({'assetClasses': assetClass}).sort({'name': 1}).to_list(1000)


@router.get("/{id}", response_model=Fund)
async def get_fund_details(id: str):
    return await db.fund.find_one({'_id': ObjectId(id)})


@router.get("/{id}/note", response_model=list[Note])
async def get_fund_notes(id: str):
    """Including draft"""
    return await db.note.find({'fundId': ObjectId(id)}).sort({'modifiedDate': -1}).to_list(1000)
