from app import app
from views import *


def run():
    app.run(host=app.config['HOST'])
