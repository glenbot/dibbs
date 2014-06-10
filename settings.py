import os

DEBUG = True
SECRET_KEY = 'acb123'
PROJECT_ROOT = os.path.abspath(os.path.dirname(__file__))

# database info
DATABASE = {
    'name': os.path.join(PROJECT_ROOT, 'dibbs.db'),
    'engine': 'peewee.SqliteDatabase',
}

# Application specific config
APP_NAME = "Clash of Clans Dibbs Machine"
APP_TAGLINE = "Call dibbs on war bases"

# Facebook settings
FACEBOOK_APP_ID = '1234'
FACEBOOK_APP_SECRET = 's3kr3t'

try:
    from settings_local import *
except:
    pass
