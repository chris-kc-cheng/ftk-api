from fastapi import APIRouter, Depends
from .user import get_current_user

router = APIRouter(prefix='/market',
                   tags=['market'],
                   dependencies=[], # Depends(get_current_user)
                   responses={404: {'description': 'Not found'}})


@router.get("/equity")
async def download_data():
    pass
