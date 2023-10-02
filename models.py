import datetime
import json
from pycountry import countries
from flask_login import UserMixin

from peewee import SqliteDatabase, CharField, BooleanField, ForeignKeyField, DateTimeField, PrimaryKeyField, TextField, \
    IntegerField
from playhouse.flask_utils import FlaskDB

DATABASE = 'secret_santa.db'
db = SqliteDatabase(DATABASE)
flask_db = FlaskDB(database=db)

country_list = ["EU"] + [c.name for c in countries]


class JSONField(TextField):
    def db_value(self, value):
        return json.dumps(value)

    def python_value(self, value):
        if value is not None:
            return json.loads(value)


class User(flask_db.Model, UserMixin):
    AVAILABLE_COUNTRIES = sorted(country_list)

    id = PrimaryKeyField()
    password = CharField(null=True)
    created = DateTimeField(default=datetime.datetime.now)
    is_admin = BooleanField(default=False)

    discord_username = CharField()

    public_key = CharField(null=True)
    private_key = CharField(null=True)

    received_gift = BooleanField(default=False)
    gift_comments = CharField(null=True)

    country = CharField(null=True, choices=[(c, c) for c in AVAILABLE_COUNTRIES])
    ship_internationally = BooleanField(default=False)

    max_match_count = IntegerField(default=1)

    def get_gift_comments(self):
        if self.gift_comments:
            return self.gift_comments
        return ""

    def get_private_key(self):
        if self.private_key:
            return self.private_key
        return ""

    def get_public_key(self):
        if self.public_key:
            return self.public_key
        return ""

    @property
    def secret_santa_public_key(self):
        try:
            return self.secret_santa_mapping[0].secret_santa.public_key
        except IndexError:
            return ""

    @property
    def secret_santa(self):
        try:
            return self.secret_santa_mapping[0].secret_santa
        except IndexError:
            return None

    @property
    def needs_preferences(self):
        return (not self.gift_comments or not self.country)

    @property
    def n_recipients(self):
        return len(self.match)

    @property
    def recipients(self):
        for match in self.match:
            yield match.match

    @property
    def address_for_secret_santa(self):
        try:
            return self.secret_santa_mapping[0].matched_address
        except IndexError:
            return ""

    def __str__(self):
        return f"{self.discord_username}"


class Match(flask_db.Model):
    secret_santa = ForeignKeyField(User, backref='match')
    match = ForeignKeyField(User, backref='secret_santa_mapping')
    matched_address = CharField(null=True)


class Settings(flask_db.Model):
    data = JSONField(null=True)


def initialize_database(app):
    flask_db.init_app(app)


if __name__ == '__main__':
    from app import app

    initialize_database(app)
    with app.app_context():
        flask_db.database.create_tables([User, Match, Settings], safe=True)
