from fastapi import FastAPI, HTTPException, Depends, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from database import engine, SessionLocal
import models
from typing import List
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv(dotenv_path="details.env")

# FastAPI app
app = FastAPI()

# It will ensure all database tables are created when the application starts
models.Base.metadata.create_all(bind=engine)

# Database Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Secret key, algorithm, and token expiry
secret_key = os.getenv("SECRET_KEY", "default-key") # It will read the SECRET_KEY mentioned in the environment variables file
algorithm = "HS256" # It is HMAC with SHA-256
access_token_expire_minutes = 30

# Using CryptContext class from passlib for bcrypt hashing function for securely storing passwords
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2PasswordBearer is used to extract a token for authentication. It can be obtained at the "token" API endpoint.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# This function is used to create a hash of the password that the user will create
def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

# This function is used for authentication, whether the hashed or plain password match
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

# We are authenticating the user by checking whether the username exists in our database and the plain password
# matches with the hashed password
def authenticate_user(db: Session, username: str, password: str):
    user = db.query(models.User).filter(models.User.username == username).first()
    if user and verify_password(password, user.hashed_password):
        return user
    return None

# The function takes user data adds the expiration time to it and encodes the data using the secret_key
# and algorithm and returns the access token to access protected parts of the app.
def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=access_token_expire_minutes)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, secret_key, algorithm=algorithm)

# This function extracts the token, decodes it to extract the username, if this fails, it would give
# an error of Invalid Token, otherwise, it would find the user with that particular username in the database
def get_current_user(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, secret_key, algorithms=algorithm)
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = db.query(models.User).filter(models.User.username == username).first()
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid token")
    return user

# It checks for an environment variable AUTHORIZED_KEYS_FILE, if it is not available it will use authorized_keys by default.
AUTHORIZED_KEYS_FILE = os.getenv("AUTHORIZED_KEYS_FILE", "authorized_keys")

def update_authorized_keys_file(db: Session):
    try:
        # Queries the Category table in the database to find all categories where is_active = True
        active_categories = db.query(models.Category).filter(models.Category.is_active).all()

        # It will create a list of active_category_ids for these active categories
        active_category_ids = [category.id for category in active_categories]

        # Queries the SSHKey table to find all SSH keys that are linked to any of the active categories
        keys_to_write = db.query(models.SSHKey).filter(models.SSHKey.categories.any(models.Category.id.in_(active_category_ids))).all()

        # Write keys to file in the correct format
        with open(AUTHORIZED_KEYS_FILE, "w") as file:
            for ssh_key in keys_to_write:
                file.write(f"{ssh_key.key}\n")
        print("authorized_keys file updated successfully.")

    except Exception as e:
        print(f"Error updating authorized_keys file: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to update authorized_keys file: {str(e)}")

# Schemas
class SSHKeyCreate(BaseModel):
    key: str
    category_ids: List[int]  # Allow multiple category IDs

class SSHKeyResponse(BaseModel):
    id: int
    key: str
    user_id: int
    category_ids: List[int]  # Return multiple category IDs

class CategoryCreate(BaseModel):
    name: str

class CategoryResponse(BaseModel):
    id: int
    name: str
    is_active: bool

class CategoryUpdate(BaseModel):
    is_active: bool

class UserCreate(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

# Endpoints

# This endpoint is used to create a new user
@app.post("/users/")
def create_user(user_data: UserCreate, db: Session = Depends(get_db)):
    existing_user = db.query(models.User).filter(models.User.username == user_data.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists") # if username already exists it would give an error

    # Hashing the password using the password hashing function created above
    hashed_password = get_password_hash(user_data.password)
    user = models.User(username=user_data.username, hashed_password=hashed_password)
    db.add(user)
    db.commit() # Saves the user in the database
    db.refresh(user)
    return {"Username": user.username, "ID": user.id}

# This endpoint takes username and password and creates a JWT access token, if the username and password
# do not exist it will print out an error that invalid username or password
@app.post("/token", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/Secure Welcome")
def secure_welcome(current_user: models.User = Depends(get_current_user)):
    return {"message": f"Hello, {current_user.username}!"}

# This endpoint is used to create the sshkeys for the user
@app.post("/keys/", status_code=status.HTTP_201_CREATED, response_model=SSHKeyResponse)
def create_ssh_key(key_data: SSHKeyCreate, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):

    # The startswith string function is used to check whether the key entered by the user is in the correct format or not
    # The following key types are taken from the following link: https://cloud.ibm.com/docs/hp-virtual-servers?topic=hp-virtual-servers-generate_ss

    if not key_data.key.startswith("ssh-rsa") and not key_data.key.startswith("ssh-ed25519") and not key_data.key.startswith(
        "ecdsa-sha2-nistp256") and not key_data.key.startswith("ecdsa-sha2-nistp384") and not key_data.key.startswith("ecdsa-sha2-nistp521"):
        raise HTTPException(status_code=400, detail="Invalid SSH Public Key Format")

    # This will get the key along with the authenticated username
    key_with_username = f"{key_data.key} {current_user.username}@hostname"

    # The following query will find all the categories in the database matching with the ones entered by the user
    categories = db.query(models.Category).filter(models.Category.id.in_(key_data.category_ids)).all()

    # We will validate if the categories entered by the user are the ones in the database using their IDs
    # If a user request a category-ID that does not exist in the database then it will print an error
    if len(categories) != len(key_data.category_ids):
        raise HTTPException(status_code=400, detail="One or more categories do not exist")

    # Create the SSHKey tied to the authenticated user
    db_key = models.SSHKey(
        key=key_with_username,  # Use the key provided by the user
        user_id=current_user.id,
        categories=categories
    )
    db.add(db_key)

    try:
        db.commit()
        db.refresh(db_key)

        # Update the authorized_keys file
        update_authorized_keys_file(db)

        # This line extracts the IDs of all categories linked to the newly created SSHKey entry
        category_ids = [category.id for category in db_key.categories]
        return {"id": db_key.id,
                "key": db_key.key,
                "user_id": db_key.user_id,
                "category_ids": category_ids}

    except Exception as e:
        # Rolls back the database transaction to avoid any incorrect updates
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to create SSH key: {str(e)}")

# This endpoint is used to assign a category to a key
@app.post("/keys/{key_id}/categories/", status_code=status.HTTP_200_OK)
def assign_category_to_key(key_id: int, category_id: int, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    # The function fetches the SSH key and category based on the provided IDs.
    # It ensures the SSH key belongs to the authenticated (current) user
    key = db.query(models.SSHKey).filter(models.SSHKey.id == key_id, models.SSHKey.user_id == current_user.id).first()
    if not key:
        raise HTTPException(status_code=404, detail="SSH key not found or you don't have access to it")

    # Fetch the category and check if it exists
    category = db.query(models.Category).filter(models.Category.id == category_id).first()
    if not category:
        raise HTTPException(status_code=404, detail="Category not found")

    # Check if the key already has this category
    if category in key.categories:
        raise HTTPException(status_code=400, detail="Category is already assigned to this key")

    # Assign the category to the key
    key.categories.append(category)
    db.commit()
    db.refresh(key)

    return {"message": f"Category {category_id} successfully assigned to key {key_id}"}

# This endpoint will list all of the keys of the authenticated user
@app.get("/keys/", response_model=List[SSHKeyResponse])
def list_ssh_keys(db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    # Listing keys to the authenticated user
    keys = db.query(models.SSHKey).filter(models.SSHKey.user_id == current_user.id).all()
    # To list all the keys to the current user, we are printing the key_id, the key, the user_id and the
    # category_id the key is assigned to
    result = []
    for key in keys:
        result.append({
            "id": key.id,
            "key": key.key,
            "user_id": key.user_id,
            "category_ids": [category.id for category in key.categories]
        })
    return result

# This endpoint will delete the keys of the authenticated user by specifying the key id
@app.delete("/keys/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_ssh_key(key_id: int, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    # It will access the key_id and the user_id from the user
    # It verifies that the key exists and belongs to the current user
    db_key = db.query(models.SSHKey).filter(models.SSHKey.id == key_id, models.SSHKey.user_id == current_user.id).first()
    if not db_key:
        raise HTTPException(status_code=404, detail="Key not found or you don't own this key")
    # Deleting the key
    db.delete(db_key)
    db.commit()

    # Update the authorized_keys file
    update_authorized_keys_file(db)

# This endpoint is used to create a new category
@app.post("/categories/", status_code=status.HTTP_201_CREATED, response_model=CategoryResponse)
def create_category(category_data: CategoryCreate, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    print(current_user)
    db_category = models.Category(**category_data.dict())
    db.add(db_category)
    db.commit()
    db.refresh(db_category)
    return db_category

# This endpoint is used to update whether the key category is active or inactive
@app.patch("/categories/{category_id}", response_model=CategoryResponse)
def update_category(category_id: int,update_data: CategoryUpdate,db: Session = Depends(get_db),current_user: models.User = Depends(get_current_user)):

    # Retrieve the category by its ID from the database
    db_category = db.query(models.Category).filter(models.Category.id == category_id).first()

    # If no category is found, it will give an error
    if not db_category:
        raise HTTPException(status_code=404, detail="Category not found")


    changes_made = False
    for key, value in update_data.dict().items(): # The input data is turned into a dictionary of key-value pair.
        if getattr(db_category, key) != value: # It checks if the current value in the category is_active is equal to the new value entered by the user
            setattr(db_category, key, value) # If it is different, means the user is updating the key category
            changes_made = True

    # Commit changes if made
    if changes_made:
        db.commit()
        db.refresh(db_category)
        update_authorized_keys_file(db)

    return db_category
