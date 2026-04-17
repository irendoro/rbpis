from datetime import datetime
from pydantic import BaseModel, field_validator


class UserCreate(BaseModel):
    username: str
    password: str
    full_name: str | None = None


class UserResponse(BaseModel):
    id: int
    username: str
    full_name: str | None
    role: str
    model_config = {"from_attributes": True}


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class PassCreate(BaseModel):
    pass_uid: str
    owner_id: int
    expires_at: datetime

    @field_validator("pass_uid")
    @classmethod
    def uid_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("pass_uid cannot be empty")
        return v


class PassResponse(BaseModel):
    id: int
    pass_uid: str
    is_active: bool
    expires_at: datetime
    model_config = {"from_attributes": True}


class ValidateRequest(BaseModel):
    pass_uid: str
    checkpoint: str
