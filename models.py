from sqlalchemy import Boolean, Column, Integer, String, ForeignKey  # Importing necessary datatypes
from sqlalchemy.orm import relationship  # Used to create relationships between tables
from database import Base  # Importing the Base class created in database.py

# We will create an association table to create a many-to-many relationship between SSHKeys and Categories
class SSHKey_Category_Association(Base):
    __tablename__ = 'keycategoriesassociation'

    key_id = Column(Integer, ForeignKey('ssh_keys.id'), primary_key=True)
    category_id = Column(Integer, ForeignKey('categories.id'), primary_key=True)


class SSHKey(Base):
    __tablename__ = 'ssh_keys'

    # I am creating 3 columns in this table: the key_id, key, and user it belongs to
    id = Column(Integer, primary_key=True, index=True)
    key = Column(String(500), unique=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    # Each SSHKey belongs to one User
    user = relationship("User", back_populates="ssh_keys")

    # Creating a many-to-many relationship with the categories table by using the keycategoriesassociation table.
    # A SSHKey can have multiple categories
    categories = relationship("Category", secondary="keycategoriesassociation", back_populates="ssh_keys")


class Category(Base):
    __tablename__ = 'categories'

    # I am creating 3 columns in this table: id, category name, and whether the category is active or not
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(50), unique=True, nullable=False)
    is_active = Column(Boolean, default=True)

    # Creating a many-to-many relationship with the SSHKey table by using the keycategoriesassociation table.
    # A category can have multiple SSHKeys
    ssh_keys = relationship("SSHKey", secondary="keycategoriesassociation", back_populates="categories")

class User(Base):
    __tablename__ = "users"

    # Columns for the User table
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False)
    hashed_password = Column(String(128), nullable=False)

    # One User can have multiple SSHKeys
    ssh_keys = relationship("SSHKey", back_populates="user")
