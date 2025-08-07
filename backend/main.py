from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, Enum
from sqlalchemy.orm import sessionmaker, relationship, declarative_base, Session
from passlib.context import CryptContext
from jose import JWTError, jwt
import enum

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# SQLAlchemy setup
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

# Auth
SECRET_KEY = "secretkey"
ALGORITHM = "HS256"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class RoleEnum(str, enum.Enum):
    admin = "admin"
    manager = "manager"
    worker = "worker"

# Models
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password = Column(String)
    role = Column(Enum(RoleEnum), default="worker")

class Client(Base):
    __tablename__ = "clients"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    contact = Column(String)

class Task(Base):
    __tablename__ = "tasks"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String)
    status = Column(String)
    assignee_id = Column(Integer, ForeignKey("users.id"))
    client_id = Column(Integer, ForeignKey("clients.id"))

    assignee = relationship("User")
    client = relationship("Client")

Base.metadata.create_all(bind=engine)

# Utils
def get_user(db, username: str):
    return db.query(User).filter(User.username == username).first()

def authenticate_user(db, username: str, password: str):
    user = get_user(db, username)
    if not user or not pwd_context.verify(password, user.password):
        return False
    return user

def create_access_token(data: dict):
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(lambda: SessionLocal())):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401)
    except JWTError:
        raise HTTPException(status_code=401)
    user = get_user(db, username=username)
    if user is None:
        raise HTTPException(status_code=401)
    return user

def get_current_admin(user: User = Depends(get_current_user)):
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admins only")
    return user

# Routes
@app.post("/register")
def register(username: str, password: str, role: RoleEnum = RoleEnum.worker, db: Session = Depends(lambda: SessionLocal())):
    user = User(username=username, password=pwd_context.hash(password), role=role)
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"msg": "User created"}

@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(lambda: SessionLocal())):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer", "role": user.role}

@app.get("/users/me")
def read_users_me(current_user: User = Depends(get_current_user)):
    return {"username": current_user.username, "role": current_user.role}

@app.post("/clients")
def create_client(name: str, contact: str, db: Session = Depends(lambda: SessionLocal()), _: User = Depends(get_current_admin)):
    client = Client(name=name, contact=contact)
    db.add(client)
    db.commit()
    return {"msg": "Client added"}

@app.get("/clients")
def list_clients(db: Session = Depends(lambda: SessionLocal()), _: User = Depends(get_current_user)):
    return db.query(Client).all()

@app.post("/tasks")
def create_task(title: str, status: str, assignee_id: int, client_id: int, db: Session = Depends(lambda: SessionLocal()), _: User = Depends(get_current_user)):
    task = Task(title=title, status=status, assignee_id=assignee_id, client_id=client_id)
    db.add(task)
    db.commit()
    return {"msg": "Task created"}

@app.get("/tasks")
def list_tasks(db: Session = Depends(lambda: SessionLocal()), _: User = Depends(get_current_user)):
    return db.query(Task).all()