import os
import motor.motor_asyncio
from typing_extensions import Annotated
from pydantic.functional_validators import BeforeValidator

client = motor.motor_asyncio.AsyncIOMotorClient(os.environ["MONGODB_HOST"])
db = client.ftkdb

PyObjectId = Annotated[str, BeforeValidator(str)]