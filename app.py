import os
from collections import defaultdict
import random
from copy import copy

from flask import Flask, redirect, url_for, request, session
from flask_admin import Admin, expose, BaseView, AdminIndexView
from flask_admin.contrib.peewee import ModelView
from flask_admin.menu import MenuLink
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
import requests
from markupsafe import Markup
from peewee import JOIN, fn

import config
from models import initialize_database, User, Match

app = Flask(__name__)

app.secret_key = config.SECRET_KEY

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)

app.config['FLASK_ADMIN_SWATCH'] = 'superhero'
initialize_database(app)


# initialize_database(app)


def users_without_secret_santa_exist():
    users = User.select()
    matches = Match.select()
    if not matches:
        # we don't want to trigger this if matching has not yet been performed
        return False
    for user in users:
        if not user.secret_santa and user.country and user.public_key:
            return True
    return False


@app.context_processor
def inject_variables():
    cwd = os.getcwd()
    directory_path = os.path.join(cwd, 'static/mp3')

    file_list = [f for f in os.listdir(directory_path) if os.path.isfile(os.path.join(directory_path, f))]

    default_song = random.choice(file_list)
    file_list.remove(default_song)

    gift_comments = ""
    public_key = ""
    private_key = ""

    if current_user.is_authenticated:
        public_key = current_user.get_public_key()
        private_key = current_user.get_private_key()
        gift_comments = current_user.get_gift_comments()

    return {
        'default_song': default_song,
        'songs': file_list,
        'users_without_secret_santa_exist': users_without_secret_santa_exist(),
        'gift_comments': gift_comments,
        'matches_exist': len(Match.select()),
        'public_key': public_key,
        'private_key': private_key
    }


class HomeView(AdminIndexView):

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('loginview.index'))

    def is_accessible(self):
        return current_user.is_authenticated

    @expose('/')
    def index(self):
        return self.render('index.html')

    @expose('/my-preferences')
    def my_preferences(self):
        return self.render('my_preferences.html')


class PreferencesView(BaseView):

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('loginview.index'))

    def is_accessible(self):
        return current_user.is_authenticated

    @expose('/')
    def index(self):
        return self.render('my_preferences.html')


class LoginView(BaseView):

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('admin.index'))

    def is_accessible(self):
        return not current_user.is_authenticated

    @expose('/')
    def index(self):
        return self.render('login.html')


def get_first_user_without_santa(users, santa):
    for user in users:
        if user.secret_santa:
            continue
        if user.id == santa.id:
            continue
        return user


def get_first_santa(users):
    for santa in users:
        if not santa.n_recipients >= santa.max_match_count:
            return santa


def create_matches(users):
    if not users:
        return
    first_user = users[0]

    counter = 0

    for i, recipient in enumerate(users):

        if recipient.secret_santa:
            continue

        if i > counter:
            counter = i

        try:
            secret_santa = users[counter + 1]
            while (secret_santa.n_recipients >= secret_santa.max_match_count) and \
                    (secret_santa.ship_internationally or (secret_santa.country == recipient.country)) \
                    and (secret_santa.id != recipient.id):
                counter += 1
                secret_santa = users[counter + 1]

        except IndexError:
            secret_santa = first_user

        if secret_santa.id != recipient.id and (
                secret_santa.ship_internationally or (secret_santa.country == recipient.country)):
            Match.create(secret_santa=secret_santa, match=recipient)


def get_first_int_user(user_list, pulled_users):
    for user in user_list:
        if user.ship_internationally and user not in pulled_users:
            return user


def get_user_pools(user_list):
    user_pool = []
    int_pool = []
    for user in user_list:
        if user.ship_internationally:
            int_pool.append(user)
        else:
            user_pool.append(user)

    return user_pool + int_pool[5:], int_pool[:5]


def match_users(should_create=False):
    users_without_secret_santa = list(
        User
        .select()
        .join(Match, JOIN.LEFT_OUTER, on=(User.id == Match.match))
        .where(Match.secret_santa.is_null(), User.public_key.is_null(False), User.country.is_null(False))
    )

    users_with_available_matches = list(
        User
        .select(User, fn.COUNT(Match.match).alias('match_count'))
        .join(Match, JOIN.LEFT_OUTER, on=(User.id == Match.secret_santa))
        .group_by(User)
        .having((fn.COUNT(Match.match) < User.max_match_count) | User.max_match_count.is_null())
        .where(User.id.not_in(users_without_secret_santa), User.public_key.is_null(False), User.country.is_null(False))
    )

    users_by_country = defaultdict(list)

    # user_pool,  = get_user_pools(users_without_secret_santa)
    santa_user_pool, santa_int_pool = get_user_pools(users_with_available_matches)

    if not santa_int_pool:

        for user in copy(users_without_secret_santa):

            if user.ship_internationally and user.n_recipients < user.max_match_count:
                santa_int_pool.append(user)
                users_without_secret_santa.remove(user)

            if len(santa_int_pool) > 5:
                break

    for user in users_without_secret_santa:
        users_by_country[user.country].append(user)

    for country in users_by_country:
        if len(users_by_country[country]) < 2 and santa_int_pool:
            users_by_country[country].append(santa_int_pool.pop())

    for santa in santa_user_pool:
        if santa.country in users_by_country:
            users_by_country[santa.country].append(santa)

    for santa in santa_int_pool:
        users_by_country[santa.country].append(santa)

    def grab_int_user_from_list(users_by_country):
        ucc = copy(users_by_country)

        for country, user_list in ucc.items():
            if len(user_list) == 1 and user_list[0].ship_internationally:
                del users_by_country[country]
                return user_list[0]

        for country, user_list in ucc.items():
            if len(user_list) > 2:
                for user in user_list:
                    if user.ship_internationally:
                        users_by_country[country].remove(user)
                        return user

    def do_the_shuffle(users_by_country):

        countries_with_all_local_only = set()

        for country, user_list in users_by_country.items():
            if all([not u.ship_internationally for u in user_list]):
                countries_with_all_local_only.add(country)

        for country in countries_with_all_local_only:
            add_user = grab_int_user_from_list(users_by_country)
            if add_user:
                users_by_country[country].append(add_user)

        bump_int_users = []

        for i, items in enumerate(users_by_country.items()):
            country, user_list = items
            if len(user_list) == 1:
                if bump_int_users:
                    if i == len(users_by_country.keys()):
                        user_list.append(bump_int_users.pop())
                    else:
                        user_list.append(bump_int_users.pop())
                else:
                    if user_list[0].ship_internationally:
                        if i == len(users_by_country.keys()):
                            users_by_country[list(users_by_country.keys())[0]].append(user_list.pop())
                        else:
                            bump_int_users.append(user_list.pop())

        if bump_int_users:
            for country, user_list in users_by_country.items():
                if user_list:
                    user_list.extend(bump_int_users)

    do_the_shuffle(users_by_country)

    for user_list in users_by_country.values():
        if should_create:
            create_matches(user_list)


class Matching(BaseView):

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('admin.index'))

    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin

    @expose('/')
    def index(self):
        return self.render('matching.html')

    @expose('/create-matches')
    def create_matches(self):
        match_users(should_create=True)
        return redirect(url_for('matching.index'))


admin = Admin(app,
              index_view=HomeView(
                  name='Home', url='/'
              ), template_mode='bootstrap3',
              base_template='custom_base.html', name="Secret Santa"
              )


class LoginMenuLink(MenuLink):

    def is_accessible(self):
        return not current_user.is_authenticated


class LogoutMenuLink(MenuLink):

    def is_accessible(self):
        return current_user.is_authenticated


admin.add_view(LoginView(name='Login', url="/login"))
admin.add_view(Matching(name='Matching', url="/matching"))
admin.add_view(PreferencesView(name='My Preferences', url="/my-preferences"))
admin.add_link(LogoutMenuLink(name='Logout', category='', url="/logout"))


class MyModelView(ModelView):

    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('loginview.index'))


class UserView(ModelView):

    def _impersonate(view, context, model, name):
        _html = f'''
            <a href="{url_for('user.impersonate', user_id=model.id)}">
                Impersonate
            </a>
        '''

        return Markup(_html)

    column_formatters = {
        'impersonate': _impersonate,
        'recipients': lambda v, c, m, n: str([str(r) for r in m.recipients]),
        'address_for_secret_santa': lambda v, c, m, n: bool(m.address_for_secret_santa),
        'has_public_key': lambda v, c, m, n: bool(m.public_key),
        'has_private_key': lambda v, c, m, n: bool(m.private_key),
    }

    column_list = (
        'discord_username', 'secret_santa', 'recipients', 'address_for_secret_santa', 'received_gift', 'created',
        'is_admin', 'impersonate', 'has_public_key', 'has_private_key', 'ship_internationally')

    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('loginview.index'))

    @expose('/impersonate/<user_id>/', methods=('GET', 'POST'))
    def impersonate(self, user_id):
        original_user = {
            'system_id': current_user.id,
            'id': session['user_id']
        }
        user = User.get(User.id == user_id)
        logout_user()
        my_user_login(user, {'id': 'null-id-for-impersonation'})
        session['original_user'] = original_user
        return redirect(url_for('admin.index'))


admin.add_view(UserView(User))


@app.route('/end_impersonation/', methods=('GET', 'POST'))
@login_required
def end_impersonation():
    original_user = User.get(id=session['original_user']['system_id'])
    discord_data = session['original_user']
    logout_user()
    my_user_login(original_user, discord_data)
    session.pop('original_user')
    return (redirect(url_for('user.index_view')))


@login_manager.user_loader
def load_user(user_id):
    user = User.get(id=user_id)
    return user


@app.route('/increase-potential', methods=['GET'])
@login_required
def increase_potential():
    if users_without_secret_santa_exist():
        current_user.max_match_count = current_user.max_match_count + 1
        current_user.save()
        match_users(should_create=True)
    return redirect(url_for('admin.index'))


@app.route('/store-gift-comments', methods=['POST'])
@login_required
def store_gift_comments():
    d = request.json
    current_user.gift_comments = d['giftComments']
    current_user.ship_internationally = d['shipInternationally']
    current_user.country = d['country']
    current_user.received_gift = d['receivedGift']
    current_user.save()
    return "success"


@app.route('/store-address', methods=['POST'])
@login_required
def store_address():
    data = request.json
    match = current_user.secret_santa_mapping[0]
    match.matched_address = data['encryptedAddress']
    match.save()
    return "success"


@app.route('/store-keys', methods=['POST'])
@login_required
def store_keys():
    data = request.json
    current_user.public_key = data['publicKey']
    current_user.private_key = data['privateKey']

    session['private_key'] = current_user.private_key if current_user.private_key is not None else ''
    session['public_key'] = current_user.public_key if current_user.public_key is not None else ''

    current_user.save()
    return "success"


@app.route('/login-with-discord')
def login_with_discord():
    discord_auth_url = f"https://discord.com/api/oauth2/authorize?client_id={config.DISCORD_APP_ID}&redirect_uri={config.DISCORD_REDIRECT_URI}&response_type=code&scope=identify"
    return redirect(discord_auth_url)


def my_user_login(user, discord_data):
    login_user(user)
    session['user_id'] = discord_data['id']
    session['private_key'] = current_user.private_key if current_user.private_key is not None else ''
    session['public_key'] = current_user.public_key if current_user.public_key is not None else ''


@app.route('/callback')
def callback():
    code = request.args.get('code')
    data = {
        'client_id': config.DISCORD_APP_ID,
        'client_secret': config.DISCORD_SECRET,
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': config.DISCORD_REDIRECT_URI,
        'scope': 'identify'
    }
    response = requests.post('https://discord.com/api/oauth2/token', data=data)
    token = response.json()['access_token']

    user_response = requests.get('https://discord.com/api/users/@me', headers={'Authorization': f'Bearer {token}'})

    user_data = user_response.json()

    user, _ = User.get_or_create(
        discord_username=user_data['username']
    )

    my_user_login(user, user_data)

    return redirect(url_for('admin.index'))


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('admin.index'))


if __name__ == '__main__':
    app.run(debug=True)
