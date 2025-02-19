from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey
from sqlalchemy.orm import sessionmaker, Session, declarative_base
from starlette.middleware.base import BaseHTTPMiddleware

# Configuration
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Database setup
DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Models
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(String)  # Roles: superadmin, admin, teacher
    branch_id = Column(Integer, ForeignKey("branches.id"), nullable=True)

class Branch(Base):
    __tablename__ = "branches"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    address = Column(String)

class Teacher(Base):
    __tablename__ = "teachers"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    branch_id = Column(Integer, ForeignKey("branches.id"))

class Student(Base):
    __tablename__ = "students"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    branch_id = Column(Integer, ForeignKey("branches.id"))
    group_id = Column(Integer, ForeignKey("groups.id"))
    teacher_id = Column(Integer, ForeignKey("teachers.id"))

class Group(Base):
    __tablename__ = "groups"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    branch_id = Column(Integer, ForeignKey("branches.id"))
    teacher_id = Column(Integer, ForeignKey("teachers.id"))

# Pydantic models
class UserCreate(BaseModel):
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

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str

# Utility functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(token: str = Depends(OAuth2PasswordBearer(tokenUrl="token"))):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    db = SessionLocal()
    user = db.query(User).filter(User.username == token_data.username).first()
    if user is None:
        raise credentials_exception
    return user

# Middleware for authentication
class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        token = request.headers.get("Authorization")
        if token and token.startswith("Bearer "):
            token = token.split("Bearer ")[1]
            try:
                user = get_current_user(token)
                request.state.current_user = user
            except Exception:
                raise HTTPException(status_code=401, detail="Not authenticated")
        else:
            request.state.current_user = None
        response = await call_next(request)
        return response

# Middleware for role-based filtering
class RoleBasedMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        current_user = getattr(request.state, "current_user", None)
        if current_user:
            if current_user.role == "admin":
                request.state.branch_id = current_user.branch_id
            elif current_user.role == "teacher":
                request.state.teacher_id = current_user.id
        response = await call_next(request)
        return response

app = FastAPI()
app.add_middleware(AuthMiddleware)
app.add_middleware(RoleBasedMiddleware)

# Authentication
@app.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    db = SessionLocal()
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# Superadmin endpoints
@app.post("/branches/", response_model=None)
async def create_branch(branch: BranchCreate, current_user: User = Depends(get_current_user)):
    if current_user.role != "superadmin":
        raise HTTPException(status_code=403, detail="Only superadmin can create branches")
    db = SessionLocal()
    db_branch = Branch(**branch.dict())
    db.add(db_branch)
    db.commit()
    db.refresh(db_branch)
    return db_branch

@app.post("/users/", response_model=None)
async def create_user(user: UserCreate, current_user: User = Depends(get_current_user)):
    if current_user.role != "superadmin":
        raise HTTPException(status_code=403, detail="Only superadmin can create users")
    db = SessionLocal()
    hashed_password = get_password_hash(user.password)
    db_user = User(**user.dict(), hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

# Admin endpoints
@app.post("/students/", response_model=None)
async def create_student(student: StudentCreate, current_user: User = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Only admin can create students")
    db = SessionLocal()
    db_student = Student(**student.dict(), branch_id=current_user.branch_id)
    db.add(db_student)
    db.commit()
    db.refresh(db_student)
    return db_student

@app.post("/groups/", response_model=None)
async def create_group(group: GroupCreate, current_user: User = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Only admin can create groups")
    db = SessionLocal()
    db_group = Group(**group.dict(), branch_id=current_user.branch_id)
    db.add(db_group)
    db.commit()
    db.refresh(db_group)
    return db_group

# Teacher endpoints
@app.get("/students/", response_model=None)
async def get_students(current_user: User = Depends(get_current_user)):
    if current_user.role != "teacher":
        raise HTTPException(status_code=403, detail="Only teacher can view students")
    db = SessionLocal()
    students = db.query(Student).filter(Student.teacher_id == current_user.id).all()
    return students

@app.get("/groups/", response_model=None)
async def get_groups(current_user: User = Depends(get_current_user)):
    if current_user.role != "teacher":
        raise HTTPException(status_code=403, detail="Only teacher can view groups")
    db = SessionLocal()
    groups = db.query(Group).filter(Group.teacher_id == current_user.id).all()
    return groups