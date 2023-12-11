from pydantic import BaseModel, Field, conlist
from datetime import datetime
from ..dependencies import PyObjectId

class Fund(BaseModel):
    id: PyObjectId = Field(alias="_id", default=None)
    name: str = Field(min_length=1)
    firm: str = Field(min_length=1)
    assetClasses: conlist(str, min_length=1)
    launchDate: datetime | None = None