from __future__ import absolute_import

from peewee import (
    DateTimeField,
    CharField,
    IntegerField,
    TextField,
    ForeignKeyField,
    BigIntegerField
)

from app import db


class User(db.Model):
    fb_id = CharField(max_length=100, null=True)
    name = CharField(max_length=75, null=True)
    username = CharField(max_length=75, null=True)
    password = CharField(max_length=64, null=True)
    coc_handle = CharField(max_length=75, null=True)

    def __unicode__(self):
        return '%s (%s)' % (self.name, self.fb_id,)


class WarBase(db.Model):
    player_name = CharField(max_length=75, null=True)


class Dibb(db.Model):
    user = ForeignKeyField(User)
    warbase = ForeignKeyField(WarBase, related_name='dibbs')
