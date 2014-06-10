from flask import Flask
from flask_peewee.db import Database

# initialize the flask application
app = Flask(__name__)

# load application settings
app.config.from_object('settings')

# initialize the database
db = Database(app)
