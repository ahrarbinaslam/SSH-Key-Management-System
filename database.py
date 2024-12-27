from sqlalchemy import create_engine # From sqlalchemy I am importing create_engine which will be used to create a connection to my database
from sqlalchemy.orm import sessionmaker # session_maker is used to create a session to interact with the database
from sqlalchemy.orm import declarative_base # declarative_base is used to define the structure of our database
from dotenv import load_dotenv
import os

load_dotenv(dotenv_path="details.env")

URL_DATABASE = os.getenv("URL_DATABASE")


engine = create_engine(URL_DATABASE) # Creating a connection with our database by providing its URL
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine) # Creating a session and using the database connection created by engine
Base = declarative_base() # Creating a base class which will be used to create the tables in the models.py file
