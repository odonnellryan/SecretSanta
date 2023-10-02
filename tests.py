import unittest
import peewee as pw
from models import User, Match
from app import match_users


class TestMatchUsers(unittest.TestCase):

    def test_matching_with_country(self):
        # match_users()
        for match in Match.select():
            assert (match.secret_santa.country == match.match.country) or (match.secret_santa.ship_internationally)
