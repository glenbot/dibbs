import logging

from flask.ext.script import Manager

from app import app
from models import (
    User,
    WarBase,
    Dibb
)

manager = Manager(app)
logging.basicConfig(level='ERROR')


@manager.command
def syncdb():
    """Create all of the database tables"""
    User.create_table(fail_silently=True)
    WarBase.create_table(fail_silently=True)
    Dibb.create_table(fail_silently=True)


@manager.command
def create_bases():
    bases = len(list(WarBase.select()))
    if bases == 0:
        for i in range(1, 51):
            print 'Creating warbase #{}'.format(i)
            wb = WarBase.create(player_name=None)
            wb.save()
    else:
        print 'Warbases have already been added'


@manager.command
def runserver():
    """Runs the Flask development server i.e. app.run()"""
    from main import run
    run()


if __name__ == "__main__":
    manager.run()
