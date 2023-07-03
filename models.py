from pydantic import BaseModel

class Register_user(BaseModel):
    name: str
    password: str