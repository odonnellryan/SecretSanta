import datetime

from flask_login import UserMixin

from peewee import SqliteDatabase, CharField, BooleanField, ForeignKeyField, DateTimeField, PrimaryKeyField
from playhouse.flask_utils import FlaskDB

DATABASE = 'secret_santa.db'
db = SqliteDatabase(DATABASE)
flask_db = FlaskDB(database=db)


class User(flask_db.Model, UserMixin):
    id = PrimaryKeyField()
    password = CharField(null=True)
    created = DateTimeField(default=datetime.datetime.now)
    is_admin = BooleanField(default=False)

    discord_username = CharField()
    discord_id = CharField(unique=True)

    country = CharField(null=True)
    international = BooleanField(default=True)

    public_key = CharField(null=True)
    encryption_salt = CharField(null=True)

    encrypted_private_key = CharField(null=True)
    encrypted_address = CharField(null=True)

    matched_user = ForeignKeyField('self', null=True, backref='match')
    received_gift = BooleanField(default=False)


def initialize_database(app):
    flask_db.init_app(app)
    with app.app_context():
        flask_db.database.create_tables([User], safe=True)
