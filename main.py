from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel
from typing import List, Optional

app = FastAPI()
security = HTTPBasic()

# Fake in-memory database
fake_users_db = {
    "superadmin": {
        "username": "superadmin",
        "password": "supersecret",
        "role": "superadmin",
        "branch_id": None
    },
    "admin1": {
        "username": "admin1",
        "password": "adminsecret",
        "role": "admin",
        "branch_id": 1
    },
    "teacher1": {
        "username": "teacher1",
        "password": "teachersecret",
        "role": "teacher",
        "branch_id": 1,
        "teacher_id": 1
    }
}

fake_branches_db = [
    {"id": 1, "name": "Branch 1", "address": "Address 1"},
    {"id": 2, "name": "Branch 2", "address": "Address 2"}
]

fake_groups_db = [
    {"id": 1, "name": "Group 1", "branch_id": 1, "teacher_id": 1},
    {"id": 2, "name": "Group 2", "branch_id": 2, "teacher_id": 2}
]

fake_students_db = [
    {"id": 1, "name": "Student 1", "branch_id": 1, "group_id": 1, "teacher_id": 1},
    {"id": 2, "name": "Student 2", "branch_id": 2, "group_id": 2, "teacher_id": 2}
]

# Pydantic models
class User(BaseModel):
    username: str
    password: str
    role: str
    branch_id: Optional[int] = None

class StudentCreate(BaseModel):
    name: str
    group_id: int
    teacher_id: int

class GroupCreate(BaseModel):
    name: str
    teacher_id: int

class BranchCreate(BaseModel):
    name: str
    address: str

# Basic Authentication
def get_current_user(credentials: HTTPBasicCredentials = Depends(security)):
    user = fake_users_db.get(credentials.username)
    if not user or user["password"] != credentials.password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return user

# Superadmin endpoints
@app.post("/branches/")
async def create_branch(branch: BranchCreate, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "superadmin":
        raise HTTPException(status_code=403, detail="Only superadmin can create branches")
    new_branch = {"id": len(fake_branches_db) + 1, **branch.dict()}
    fake_branches_db.append(new_branch)
    return new_branch

@app.post("/users/")
async def create_user(user: User, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "superadmin":
        raise HTTPException(status_code=403, detail="Only superadmin can create users")
    if user.username in fake_users_db:
        raise HTTPException(status_code=400, detail="Username already exists")
    fake_users_db[user.username] = user.dict()
    return {"message": "User created successfully", "user": user}

# Admin endpoints
@app.post("/students/")
async def create_student(student: StudentCreate, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Only admin can create students")
    new_student = {"id": len(fake_students_db) + 1, **student.dict(), "branch_id": current_user["branch_id"]}
    fake_students_db.append(new_student)
    return new_student

@app.post("/groups/")
async def create_group(group: GroupCreate, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Only admin can create groups")
    new_group = {"id": len(fake_groups_db) + 1, **group.dict(), "branch_id": current_user["branch_id"]}
    fake_groups_db.append(new_group)
    return new_group

# Teacher endpoints
@app.get("/students/")
async def get_students(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "teacher":
        raise HTTPException(status_code=403, detail="Only teacher can view students")
    students = [student for student in fake_students_db if student["teacher_id"] == current_user.get("teacher_id")]
    return students

@app.get("/groups/")
async def get_groups(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "teacher":
        raise HTTPException(status_code=403, detail="Only teacher can view groups")
    groups = [group for group in fake_groups_db if group["teacher_id"] == current_user.get("teacher_id")]
    return groups

# Public endpoint to view branches (for testing)
@app.get("/branches/")
async def get_branches():
    return fake_branches_db