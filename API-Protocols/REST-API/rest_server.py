import os
import re
from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, field_validator

API_TOKEN = os.getenv("API_TOKEN", "YOUR_TOKEN")
bearer_scheme = HTTPBearer(auto_error=False)


def require_token(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    if credentials is None or credentials.credentials != API_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")


app = FastAPI(dependencies=[Depends(require_token)])
users_by_id: dict[int, dict] = {}
next_user_id = 1


class UserPayload(BaseModel):
    name: str
    email: str

    @field_validator("name")
    @classmethod
    def name_not_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("name must not be empty")
        return value.strip()

    @field_validator("email")
    @classmethod
    def email_valid(cls, value: str) -> str:
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", value.strip()):
            raise ValueError("invalid email address")
        return value.strip()


def email_in_use(email: str, exclude_id: int | None = None) -> bool:
    return any(
        u["email"] == email and u["id"] != exclude_id
        for u in users_by_id.values()
    )


@app.post("/users", status_code=201)
def create_user(payload: UserPayload):
    global next_user_id
    if email_in_use(payload.email):
        raise HTTPException(status_code=409, detail="Email already exists")
    user_record = {"id": next_user_id, **payload.model_dump()}
    users_by_id[next_user_id] = user_record
    next_user_id += 1
    return user_record


@app.get("/users")
def list_users():
    return list(users_by_id.values())


@app.get("/users/{user_id}")
def get_user(user_id: int):
    if user_id not in users_by_id:
        raise HTTPException(status_code=404, detail="User not found")
    return users_by_id[user_id]


@app.put("/users/{user_id}")
def update_user(user_id: int, payload: UserPayload):
    if user_id not in users_by_id:
        raise HTTPException(status_code=404, detail="User not found")
    if email_in_use(payload.email, exclude_id=user_id):
        raise HTTPException(status_code=409, detail="Email already exists")
    users_by_id[user_id] = {"id": user_id, **payload.model_dump()}
    return users_by_id[user_id]


@app.delete("/users/{user_id}", status_code=204)
def delete_user(user_id: int):
    if users_by_id.pop(user_id, None) is None:
        raise HTTPException(status_code=404, detail="User not found")