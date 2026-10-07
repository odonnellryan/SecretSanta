"""
Run with:  python -m unittest tests -v
Uses a throwaway sqlite file so the real secret_santa.db is never touched. Needs a config.py (any values work).
"""
import os
import random
import tempfile
import unittest
from collections import Counter

from models import db, User, Match, EU

_tmp = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
_tmp.close()
db.init(_tmp.name)

from app import app  # noqa: E402  (must come after db.init so the app binds to the temp db)
from matching import match_users, plan_matches, can_ship, prior_pairs  # noqa: E402

US, CA, UK, DE, FR = "United States", "Canada", "United Kingdom", "Germany", "France"


def make_users(spec):
    """spec: list of (country, ship_internationally)."""
    return [User.create(discord_username=f"u{i}_{c[:2]}{'I' if intl else ''}", country=c, ship_internationally=intl,
                        public_key="pk", active_this_year=True) for i, (c, intl) in enumerate(spec)]


def active_matches():
    return list(Match.select().where(Match.is_active == True))


def perfect_matching_exists(users, prior=frozenset()):
    """Reference check: can everyone give one and get one, avoiding `prior` pairs?"""
    n = len(users)
    match_r = [-1] * n

    def try_k(i, seen):
        for j in range(n):
            if j in seen or not can_ship(users[i], users[j]) or (users[i].id, users[j].id) in prior:
                continue
            seen.add(j)
            if match_r[j] == -1 or try_k(match_r[j], seen):
                match_r[j] = i
                return True
        return False

    return all(try_k(i, set()) for i in range(n))


class DBTestCase(unittest.TestCase):

    def setUp(self):
        self.ctx = app.app_context()
        self.ctx.push()
        db.create_tables([User, Match], safe=True)
        Match.delete().execute()
        User.delete().execute()
        random.seed(0)

    def tearDown(self):
        self.ctx.pop()

    def assert_valid_assignment(self, users):
        matches = active_matches()
        santas = Counter(m.secret_santa_id for m in matches)
        recips = Counter(m.match_id for m in matches)
        for u in users:
            self.assertEqual(recips[u.id], 1, f"{u} should have exactly one santa")
            self.assertEqual(santas[u.id], 1, f"{u} should give exactly one gift")
        for m in matches:
            self.assertTrue(can_ship(m.secret_santa, m.match), f"{m.secret_santa} can't ship to {m.match}")

    def two_cycles(self):
        nxt = {m.secret_santa_id: m.match_id for m in active_matches()}
        return sum(1 for a, b in nxt.items() if nxt.get(b) == a) // 2


class TestMatching(DBTestCase):

    def test_everyone_matched_domestic(self):
        users = make_users([(US, False)] * 7)
        match_users(seed=1)
        self.assert_valid_assignment(users)

    def test_shipping_rules(self):
        users = make_users([(US, False)] * 3 + [(US, True)] * 2 + [(CA, True), (UK, True)])
        match_users(seed=1)
        self.assert_valid_assignment(users)

    def test_eu_can_give_to_eu_members_only(self):
        eu = User.create(discord_username="eu", country=EU, public_key="pk", active_this_year=True)
        de = User.create(discord_username="de", country=DE, public_key="pk", active_this_year=True)
        us = User.create(discord_username="us", country=US, public_key="pk", active_this_year=True)
        self.assertTrue(can_ship(eu, de))
        self.assertFalse(can_ship(eu, us))
        self.assertFalse(can_ship(de, eu))  # Germany isn't "European Union"; only int'l shippers reach EU folks

    def test_feasible_pools_always_complete(self):
        """Random pools: whenever a complete assignment exists, we find one."""
        countries = [US] * 6 + [CA] * 2 + [UK] * 2 + [DE, FR, EU]
        checked = 0
        for trial in range(60):
            random.seed(trial)
            Match.delete().execute()
            User.delete().execute()
            spec = [(random.choice(countries), random.random() < 0.35) for _ in range(random.randint(3, 16))]
            users = make_users(spec)
            if not perfect_matching_exists(users):
                continue
            checked += 1
            match_users(seed=trial)
            self.assert_valid_assignment(users)
        self.assertGreater(checked, 10)

    def test_prefers_one_big_cycle_over_pairs(self):
        users = make_users([(US, False)] * 8)
        match_users(seed=3)
        self.assert_valid_assignment(users)
        self.assertEqual(self.two_cycles(), 0)
        nxt = {m.secret_santa_id: m.match_id for m in active_matches()}
        node, seen = users[0].id, set()
        while node not in seen:
            seen.add(node)
            node = nxt[node]
        self.assertEqual(len(seen), 8, "expected a single cycle through everyone")

    def test_avoids_prior_year_pairs(self):
        users = make_users([(US, False)] * 6)
        match_users(seed=1)
        prior = {(m.secret_santa_id, m.match_id) for m in active_matches()}
        Match.update(is_active=False).execute()
        match_users(seed=2)
        self.assert_valid_assignment(users)
        repeats = [(m.secret_santa, m.match) for m in active_matches() if (m.secret_santa_id, m.match_id) in prior]
        self.assertEqual(repeats, [])

    def test_forced_repeat_still_matches(self):
        # the lone domestic Canadian can only ever give to the one int'l Canadian
        users = make_users([(CA, False), (CA, True)] + [(US, False)] * 3 + [(US, True)])
        match_users(seed=1)
        Match.update(is_active=False).execute()
        match_users(seed=2)
        self.assert_valid_assignment(users)
        self.assertEqual(len([m for m in active_matches() if (m.secret_santa_id, m.match_id) in prior_pairs()]), 1)

    def test_infeasible_pool_leaves_only_the_unavoidable(self):
        # domestic Canadian has no one to give to, so exactly one person ends up without a santa
        users = make_users([(CA, False)] + [(US, False)] * 3 + [(US, True)])
        plan = match_users(seed=1)
        recips = Counter(m.match_id for m in active_matches())
        self.assertEqual(sum(recips[u.id] == 0 for u in users), 1)
        self.assertEqual(plan.score()[0], 1)

    def test_rerun_only_fills_gaps(self):
        users = make_users([(US, False)] * 5)
        match_users(seed=1)
        before = {(m.secret_santa_id, m.match_id) for m in active_matches()}
        match_users(seed=2)
        after = {(m.secret_santa_id, m.match_id) for m in active_matches()}
        self.assertEqual(before, after)
        self.assert_valid_assignment(users)

    def test_extra_capacity_used_only_when_needed(self):
        users = make_users([(CA, False)] + [(US, False)] * 3 + [(US, True)])
        match_users(seed=1)
        tiny_tim = next(u for u in users if u.secret_santa is None)
        volunteer = next(u for u in users if u.country == US and u.id != tiny_tim.id and can_ship(u, tiny_tim))
        volunteer.max_match_count = 2
        volunteer.save()
        match_users(seed=1)
        self.assertEqual(User.get_by_id(tiny_tim.id).secret_santa.id, volunteer.id)
        self.assertEqual(User.get_by_id(volunteer.id).n_recipients, 2)

    def test_inactive_and_keyless_users_are_skipped(self):
        users = make_users([(US, False)] * 4)
        User.create(discord_username="lurker", country=US, public_key="pk", active_this_year=False)
        User.create(discord_username="nokey", country=US, public_key=None, active_this_year=True)
        match_users(seed=1)
        self.assert_valid_assignment(users)
        self.assertEqual(len(active_matches()), 4)

    def test_empty_pool(self):
        self.assertIsNone(match_users())
        self.assertIsNone(plan_matches([], set()))


class TestRoutes(DBTestCase):

    def login(self, client, user):
        with client.session_transaction() as sess:
            sess['_user_id'] = str(user.id)
            sess['user_id'] = 'discord-id'

    @staticmethod
    def hit(client, method, url, **kw):
        # the app opens its own connection per request; close ours from any direct queries first
        if not db.is_closed():
            db.close()
        return getattr(client, method)(url, **kw)

    def test_clear_matches_archives_and_resets_users(self):
        users = make_users([(US, False)] * 4)
        users[0].is_admin = True
        users[0].max_match_count = 3
        users[0].save()
        match_users(seed=1)
        client = app.test_client()
        self.login(client, users[0])
        r = self.hit(client, 'post', '/matching/clear-matches', data={'confirmation': 'CLEAR MATCHES'})
        self.assertEqual(r.status_code, 302)
        self.assertEqual(Match.select().where(Match.is_active == True).count(), 0)
        self.assertEqual(Match.select().count(), 4, "archived, not deleted")
        self.assertEqual(User.select().where(User.active_this_year == True).count(), 0)
        self.assertEqual(User.get_by_id(users[0].id).max_match_count, 1)

    def test_clear_matches_requires_confirmation(self):
        users = make_users([(US, False)] * 4)
        users[0].is_admin = True
        users[0].save()
        match_users(seed=1)
        client = app.test_client()
        self.login(client, users[0])
        self.hit(client, 'post', '/matching/clear-matches', data={'confirmation': 'nope'})
        self.assertEqual(Match.select().where(Match.is_active == True).count(), 4)

    def test_clear_matches_for_testing_still_exists(self):
        users = make_users([(US, False)] * 3)
        users[0].is_admin = True
        users[0].save()
        match_users(seed=1)
        client = app.test_client()
        self.login(client, users[0])
        self.hit(client, 'get', '/matching/clear-matches-for-testing')
        self.assertEqual(Match.select().where(Match.is_active == True).count(), 0)

    def test_mark_shipped_ignores_archived_rows(self):
        santa, recipient = make_users([(US, False)] * 2)
        Match.create(secret_santa=santa, match=recipient, is_active=False)  # last year, same pairing
        Match.create(secret_santa=recipient, match=santa, is_active=False)
        this_year = Match.create(secret_santa=santa, match=recipient)
        client = app.test_client()
        self.login(client, santa)
        self.hit(client, 'post', f'/mark-shipped/{recipient.id}/', data={'tracking_id': 'TRACK123'})
        this_year = Match.get_by_id(this_year.id)
        self.assertTrue(this_year.ss_shipped)
        self.assertEqual(this_year.tracking_key, 'TRACK123')
        self.assertFalse(any(m.ss_shipped for m in Match.select().where(Match.is_active == False)))
        self.hit(client, 'get', f'/unmark-shipped/{recipient.id}/')
        self.assertFalse(Match.get_by_id(this_year.id).ss_shipped)

    def test_mark_shipped_only_by_the_santa(self):
        santa, recipient, other = make_users([(US, False)] * 3)
        m = Match.create(secret_santa=santa, match=recipient)
        client = app.test_client()
        self.login(client, other)
        self.hit(client, 'post', f'/mark-shipped/{recipient.id}/', data={'tracking_id': 'X'})
        self.assertFalse(Match.get_by_id(m.id).ss_shipped)

    def test_plus_one_gives_tiny_tim_to_the_clicker_only(self):
        users = make_users([(CA, False)] + [(US, False)] * 3 + [(US, True)])
        match_users(seed=1)
        tiny_tim = next(u for u in users if u.secret_santa is None)
        clicker = next(u for u in users if u.country == US and u.id != tiny_tim.id and can_ship(u, tiny_tim))
        bystander = next(u for u in users if u.id not in (tiny_tim.id, clicker.id) and u.country == US)
        bystander.max_match_count = 2  # stale carry-over from a prior year must not be used
        bystander.save()
        client = app.test_client()
        self.login(client, clicker)
        self.hit(client, 'get', '/increase-potential')
        self.assertEqual(User.get_by_id(tiny_tim.id).secret_santa.id, clicker.id)
        self.assertEqual(User.get_by_id(bystander.id).n_recipients, 1)

    def test_plus_one_reverts_when_clicker_cannot_ship(self):
        users = make_users([(CA, False), (US, False), (US, False), (US, True)])
        match_users(seed=1)
        tiny_tim = next(u for u in users if u.secret_santa is None)
        clicker = next(u for u in users if not can_ship(u, tiny_tim) and u.id != tiny_tim.id)
        client = app.test_client()
        self.login(client, clicker)
        self.hit(client, 'get', '/increase-potential')
        self.assertEqual(User.get_by_id(clicker.id).max_match_count, 1)
        self.assertIsNone(User.get_by_id(tiny_tim.id).secret_santa)


class TestDiscordIdentity(DBTestCase):

    def test_lookup_by_id_then_username(self):
        from app import find_or_create_user
        old = User.create(discord_username="oldname", country=US, public_key="pk")
        u = find_or_create_user({'id': 123, 'username': 'oldname'})
        self.assertEqual(u.id, old.id)
        self.assertEqual(u.discord_id, '123')
        u.save()
        renamed = find_or_create_user({'id': 123, 'username': 'newname'})
        self.assertEqual(renamed.id, old.id)
        self.assertEqual(renamed.discord_username, 'newname')
        stranger = find_or_create_user({'id': 456, 'username': 'someone'})
        self.assertNotEqual(stranger.id, old.id)


if __name__ == '__main__':
    unittest.main()
