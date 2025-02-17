from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from faker import Faker
from typing import List, Optional
import datetime

app = FastAPI()
fake = Faker()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class User(BaseModel):
    username: str
    password: str
    role: str
    branch: Optional[str] = None

class Branch(BaseModel):
    id: str
    name: str
    address: str

fake_users_db = {
    "super_admin": User(
        username="super_admin",
        password="supersecret",
        role="super_admin"
    ),
    "admin1": User(
        username="admin1",
        password="adminsecret",
        role="admin",
        branch="branch1"
    ),
    "user1": User(
        username="user1",
        password="usersecret",
        role="user"
    )
}

fake_branches_db = [
    Branch(id="branch1", name=fake.company(), address=fake.address()),
    Branch(id="branch2", name=fake.company(), address=fake.address()),
    Branch(id="branch3", name=fake.company(), address=fake.address())
]

def fake_decode_token(token):
    user = fake_users_db.get(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user

def get_current_user(token: str = Depends(oauth2_scheme)):
    return fake_decode_token(token)

@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user_dict = fake_users_db.get(form_data.username)
    if not user_dict:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    if user_dict.password != form_data.password:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    return {"access_token": user_dict.username, "token_type": "bearer"}

@app.get("/branches/")
async def get_branches(current_user: User = Depends(get_current_user)):
    if current_user.role == "super_admin":
        return fake_branches_db
    elif current_user.role == "admin":
        return [branch for branch in fake_branches_db if branch.id == current_user.branch]
    else:
        return {"message": "You don't have permission to view branches"}

@app.get("/branches/{branch_id}")
async def get_branch(branch_id: str, current_user: User = Depends(get_current_user)):
    if current_user.role != "super_admin" and (current_user.role == "admin" and current_user.branch != branch_id):
        raise HTTPException(status_code=403, detail="Access denied")
    branch = next((branch for branch in fake_branches_db if branch.id == branch_id), None)
    if not branch:
        raise HTTPException(status_code=404, detail="Branch not found")
    return branch



