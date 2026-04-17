from datetime import datetime, timezone

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError
from sqlalchemy.orm import Session

from . import models, schemas
from .auth import (
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
)
from .database import Base, engine, get_db

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="СКУД - Менеджер корпоративных пропусков",
    description="Корпоративная система контроля и управления доступом",
    version="0.1.0",
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")


# Helpers

def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> models.User:
    try:
        payload = decode_access_token(token)
        user = db.query(models.User).filter(models.User.username == payload["sub"]).first()
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user


def require_admin(current_user: models.User = Depends(get_current_user)) -> models.User:
    if current_user.role != "ADMIN":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin only")
    return current_user


def require_pass_access(pass_obj: models.Pass, current_user: models.User) -> None:
    if current_user.role == "ADMIN":
        return
    if pass_obj.owner_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")


# Auth

@app.post("/register", response_model=schemas.UserResponse, status_code=status.HTTP_201_CREATED)
def register(data: schemas.UserCreate, db: Session = Depends(get_db)):
    if db.query(models.User).filter(models.User.username == data.username).first():
        raise HTTPException(status_code=400, detail="Username already taken")
    user = models.User(
        username=data.username,
        hashed_password=hash_password(data.password),
        full_name=data.full_name,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@app.post("/login", response_model=schemas.Token)
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == form.username).first()
    if not user or not verify_password(form.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect credentials")
    return {"access_token": create_access_token(user.username)}


# Passes

@app.get("/passes/me", response_model=list[schemas.PassResponse])
def my_passes(current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(models.Pass).filter(models.Pass.owner_id == current_user.id).all()


@app.get("/passes/{pass_id}", response_model=schemas.PassResponse)
def get_pass(
    pass_id: int,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    p = db.query(models.Pass).filter(models.Pass.id == pass_id).first()
    if not p:
        raise HTTPException(status_code=404, detail="Pass not found")
    require_pass_access(p, current_user)
    return p


@app.post("/passes", response_model=schemas.PassResponse, status_code=status.HTTP_201_CREATED)
def create_pass(
    data: schemas.PassCreate,
    admin: models.User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    p = models.Pass(**data.model_dump(), issued_by=admin.id)
    db.add(p)
    db.commit()
    db.refresh(p)
    return p


@app.put("/passes/{pass_id}/block")
def block_pass(
    pass_id: int,
    admin: models.User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    p = db.query(models.Pass).filter(models.Pass.id == pass_id).first()
    if not p:
        raise HTTPException(status_code=404, detail="Pass not found")
    p.is_active = False
    db.commit()
    return {"detail": "Pass blocked", "pass_id": pass_id}


# Turnstile validation (mTLS planned at infrastructure level)

@app.post("/validate")
def validate_pass(req: schemas.ValidateRequest, db: Session = Depends(get_db)):
    p = db.query(models.Pass).filter(models.Pass.pass_uid == req.pass_uid).first()
    allowed = bool(p and p.is_active and p.expires_at > datetime.now(timezone.utc).replace(tzinfo=None))
    log = models.AccessLog(pass_uid=req.pass_uid, checkpoint=req.checkpoint, allowed=allowed)
    db.add(log)
    db.commit()
    return {"allowed": allowed}


# Report

@app.get("/report")
def generate_report(admin: models.User = Depends(require_admin)):
    return {
        "report": "SKUD report OK",
        "generated_by": admin.username,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
