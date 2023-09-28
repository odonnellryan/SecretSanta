import unittest
import peewee as pw
from models import User, Match
from app import match_users

test_db = pw.SqliteDatabase(':memory:')


class TestMatchUsers(unittest.TestCase):

    def setUp(self):
        test_db.bind([User, Match])

        test_db.create_tables([User, Match])

        self.countries = ['Country1', 'Country2', 'Country3', 'Country4', 'Country5', 'Country6', 'Country7',
                          'Country8', 'Country9', 'Country10']

        self.users = []
        for i in range(50):  # You can adjust the number of users as needed
            country = self.countries[i % 10]
            user = User.create(
                country=country,
                ship_internationally=(i % 2 == 0),
                discord_username=f"{i}",
            )
            self.users.append(user)

        user = User.create(
            country="One User Country 1",
            ship_internationally=False,
            discord_username=f"OUC 1",
        )
        self.users.append(user)

        user = User.create(
            country="One User Country 2",
            ship_internationally=False,
            discord_username=f"OUC 2",
        )

        self.users.append(user)

    def test_matching_with_country(self):
        match_users(self.users, should_create=True)

        for user in self.users:
            print(user.discord_username, user.secret_santa, user.recipient, user.ship_internationally, user.country)


if __name__ == '__main__':
    unittest.main()
