import os
import random
from typing import List, Dict

import requests
from flask import Flask, redirect, url_for, request, session
from flask_admin import Admin, expose, BaseView, AdminIndexView
from flask_admin.contrib.peewee import ModelView
from flask_admin.menu import MenuLink
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from markupsafe import Markup

import config
from models import initialize_database, User, Match

app = Flask(__name__)

app.secret_key = config.SECRET_KEY

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)

app.config['FLASK_ADMIN_SWATCH'] = 'superhero'
initialize_database(app)


def get_users_without_secret_santa():
    users = User.select()
    matches = list(Match.select())

    if not matches:
        return [None]

    for user in users:
        if not user.secret_santa and user.country and user.public_key:
            yield user


def users_without_secret_santa_exist():
    users = list(get_users_without_secret_santa())
    for u in users:
        if u:
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


class CountryGroup:

    def __init__(self, user: User):
        self.country: str = user.country
        self.users: List[User] = [user]

    def has_odd_match_count(self):
        # should return true if there is only ONE user who's not i
        check_non_country = [u for u in self.users if u.country != self.country]
        check_is_c_is_int = [u for u in self.users if u.country == self.country and u.ship_internationally]
        return len(check_non_country) == 1 and  len(check_is_c_is_int) == 1

    def add_user(self, user: User):
        self.users.append(user)

    def __len__(self):
        return len(self.users)

    def n_available_santas(self):
        return len([u for u in self.users if u and u.is_eligible_for_ss()])

    def get_first_avail_secret_santa(self, international=False):
        for u in self.users:
            if not u:
                continue
            if international and not u.ship_internationally:
                continue
            if u.is_eligible_for_ss():
                return u


class UserGroup:

    def __init__(self, users: List[User]):
        self.users = users
        self.countries: Dict[str, CountryGroup] = {}

        for user in self.users:
            if not user.eligible_for_participation():
                continue
            if user.country in self.countries:
                self.countries[user.country].add_user(user)
            else:
                self.countries[user.country] = CountryGroup(user)

    def get_first_avail_secret_santa(self, country, user=None, international=False, remove=True):

        n_avail_santas = 0
        if country in self.countries:
            n_avail_santas = self.countries[country].n_available_santas()

        if n_avail_santas > 2 or n_avail_santas == 1:
            ss = self.countries[country].get_first_avail_secret_santa(international=international)
            if remove:
                self.countries[country].users.remove(ss)
            return ss

        for cg in sorted(self.countries.values(), key=lambda c: c.n_available_santas(), reverse=True):
            if cg.n_available_santas() == 2:
                continue
            ss = cg.get_first_avail_secret_santa(international=international)
            if ss:
                if user:
                    if user.id == ss.id:
                        continue
                if remove:
                    cg.users.remove(ss)
                return ss

    def consolidate_countries(self):
        pass


def create_matches(country_group: CountryGroup):
    if not country_group:
        return

    ss = country_group.get_first_avail_secret_santa()
    if ss is None:
        return
    first_user = ss
    for recipient in country_group.users:

        if ss and ss.can_be_secret_santa(recipient):
            Match.create(secret_santa=ss, match=recipient)
            ss = recipient

    if ss.can_be_secret_santa(first_user):
        Match.create(secret_santa=ss, match=first_user)


def match_users_for_tiny_tims():
    users_who_can_be_santa = [u for u in User.select() if u.is_eligible_for_ss()]
    users_without_secret_santas = get_users_without_secret_santa()
    for recipient in users_without_secret_santas:
        random.shuffle(users_who_can_be_santa)
        for santa in users_who_can_be_santa:
            if santa.can_be_secret_santa(recipient):
                Match.create(secret_santa=santa, match=recipient)


def match_users():
    iu = list(User.select().where(User.ship_internationally == True))
    random.shuffle(iu)
    niu = list(User.select().where(User.ship_internationally == False))
    random.shuffle(niu)
    int_users = UserGroup(iu)
    non_int_users = UserGroup(niu)

    for country in non_int_users.countries.values():
        if len(country.users) < 2 or country.has_odd_match_count():
            ss = int_users.get_first_avail_secret_santa(country.country)
            if ss:
                country.users.append(ss)

    for country in sorted(int_users.countries.values(), key=lambda c: len(c)):
        for user in country.users:
            if country.country in non_int_users.countries:
                non_int_users.countries[country.country].add_user(user)
            else:
                non_int_users.countries[country.country] = CountryGroup(user)
        country.users = []

    # tracked_users =

    for country in sorted(non_int_users.countries.values(), key=lambda c: len(c)):
        if len(country) == 1 or country.has_odd_match_count():
            ss = non_int_users.get_first_avail_secret_santa(None, country.users[0])
            non_int_users.countries[country.country].add_user(ss)

    for country in sorted(non_int_users.countries.values(), key=lambda c: len(c)):
        create_matches(country)

    users_without_ss = list(get_users_without_secret_santa())

    int_users = UserGroup(iu)

    for u in users_without_ss:
        ss = int_users.get_first_avail_secret_santa(None, international=True, user=u)
        if ss is None:
            continue
        while not ss.can_be_secret_santa(u):
            ss = non_int_users.get_first_avail_secret_santa(None, international=True, user=u)
            if ss is None:
                continue
        Match.create(secret_santa=ss, match=u)


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
        match_users()
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

    can_delete = False

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
        match_users_for_tiny_tims()
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
