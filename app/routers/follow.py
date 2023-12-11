from typing_extensions import Annotated
from fastapi import APIRouter, Depends
from bson import ObjectId
from ..dependencies import db
from .user import User, get_current_user
from .model import Fund

router = APIRouter(prefix='/follow',
                   tags=['follow'],
                   dependencies=[Depends(get_current_user)],
                   responses={404: {'description': 'Not found'}})


@router.get("/", response_model=list[Fund])
async def get_followed_funds(current_user: Annotated[User, Depends(get_current_user)]):
    return await db.fund.find({'_id': {'$in': list(map(lambda x: ObjectId(x), current_user.followed))}}).to_list(1000)


@router.get("/{fundId}", response_model=bool)
async def is_fund_followed(fundId: str, current_user: Annotated[User, Depends(get_current_user)]):
    return await db.user.find_one({'_id': ObjectId(current_user.id), 'followed': ObjectId(fundId)}) is not None


@router.post("/{fundId}", response_model=bool)
async def follow_fund(fundId: str, current_user: Annotated[User, Depends(get_current_user)]):
    fund = await db.fund.find_one({'_id': ObjectId(fundId)})
    if fundId in current_user.followed:
        await db.user.update_one({'_id': ObjectId(current_user.id)},
                                 {'$pull': {'followed': fund['_id']}})
        return False
    else:
        await db.user.update_one({'_id': ObjectId(current_user.id)},
                                 {'$addToSet': {'followed': fund['_id']}})
        return True
