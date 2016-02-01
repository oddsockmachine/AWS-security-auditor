from peewee import *
from datetime import datetime

db = SqliteDatabase('secgrps.db')
db.connect()

class SecGrp(Model):
    name = CharField()
    description = CharField()
    region = CharField()
    created = DateField()
    class Meta:
        database = db

class Instance(Model):
    sec_grp = ForeignKeyField(SecGrp, related_name='instances')
    name = CharField()
    ip = CharField()
    description = CharField()
    region = CharField()
    state = CharField()
    created = DateField()
    class Meta:
        database = db

class FWRule(Model):
    sec_grp = ForeignKeyField(SecGrp, related_name='firewall_rules')
    flag = CharField()
    cidr = CharField()
    description = CharField()
    port = CharField()
    created = DateField()
    class Meta:
        database = db
