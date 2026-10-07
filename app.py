import os
import random

import requests
from flask import Flask, redirect, url_for, request, session, flash
from flask_admin import Admin, expose, BaseView, AdminIndexView
from flask_admin.contrib.peewee import ModelView
from flask_admin.menu import MenuLink
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from markupsafe import Markup

import config
from matching import match_users, summarize
from models import initialize_database, User, Match

app = Flask(__name__)

app.secret_key = config.SECRET_KEY

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)

app.config['FLASK_ADMIN_SWATCH'] = 'superhero'
initialize_database(app)


@app.before_request
def mark_user_active():
    """Mark any logged-in user as active for this year's matching."""
    if current_user.is_authenticated and not current_user.active_this_year:
        current_user.active_this_year = True
        current_user.save()


def get_users_without_secret_santa():
    """Active, eligible users with no santa this year. Empty until matching has run at all."""
    active_matches = Match.select().where(Match.is_active == True)
    if not active_matches.exists():
        return []
    matched = active_matches.select(Match.match)
    return list(User.select().where(
        (User.active_this_year == True) & User.country.is_null(False) & User.public_key.is_null(False)
        & User.id.not_in(matched)))


def users_without_secret_santa_exist():
    return bool(get_users_without_secret_santa())


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
        'matches_exist': len(Match.select().where(Match.is_active == True)),
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


class Matching(BaseView):

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('admin.index'))

    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin

    @expose('/')
    def index(self):
        active_user_count = User.select().where(User.active_this_year == True).count()
        return self.render('matching.html', active_user_count=active_user_count)

    @expose('/create-matches')
    def create_matches(self):
        plan = match_users()
        flash(summarize(plan), 'info')
        return redirect(url_for('matching.index'))

    @expose('/clear-matches', methods=['POST'])
    def clear_matches(self):
        confirmation = request.form.get('confirmation', '')
        if confirmation == 'CLEAR MATCHES':
            # Mark all active matches as inactive instead of deleting them
            Match.update(is_active=False).where(Match.is_active == True).execute()
            # Everyone starts next year inactive, with a single gift to give, until they log in again
            User.update(active_this_year=False, max_match_count=1, received_gift=False).execute()
            flash('Matches archived and all users reset for the new year.', 'info')
        else:
            flash('Confirmation text did not match; nothing was changed.', 'error')
        return redirect(url_for('matching.index'))

    @expose('/clear-matches-for-testing', methods=['GET'])
    def clear_matches_for_testing(self):
        Match.update(is_active=False).where(Match.is_active == True).execute()
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


admin.add_view(LoginView(name='Log In and Sign Up For Secret Santa', url="/login"))
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
        'is_admin', 'active_this_year', 'impersonate', 'has_public_key', 'has_private_key', 'ship_internationally')

    form_columns = ('discord_username', 'discord_id', 'is_admin', 'active_this_year', 'ship_internationally',
                    'country', 'gift_comments', 'received_gift', 'max_match_count')

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


def my_active_match_for(recipient_id):
    """This year's match where current_user is the santa of recipient_id, or None."""
    return Match.get_or_none((Match.match_id == int(recipient_id)) & (Match.secret_santa_id == current_user.id)
                             & (Match.is_active == True))


@app.route('/mark-shipped/<recipient_id>/', methods=['GET', 'POST'])
@login_required
def mark_shipped(recipient_id=None):
    recip = my_active_match_for(recipient_id)
    if recip is not None and request.method == 'POST':
        tracking_id = request.form.get('tracking_id')
        recip.ss_shipped = True
        recip.tracking_key = tracking_id  # Assign the tracking ID
        recip.save()
    return redirect(url_for('admin.index'))


@app.route('/unmark-shipped/<recipient_id>/', methods=['GET'])
@login_required
def unmark_shipped(recipient_id=None):
    recip = my_active_match_for(recipient_id)
    if recip is not None:
        recip.ss_shipped = False
        recip.save()
    return redirect(url_for('admin.index'))


@app.route('/increase-potential', methods=['GET'])
@login_required
def increase_potential():
    """Volunteer to give one more gift, and hand the clicker a user who has no santa if they can ship to them."""
    if users_without_secret_santa_exist():
        before = current_user.n_recipients
        current_user.max_match_count = current_user.max_match_count + 1
        current_user.save()
        match_users()
        if current_user.n_recipients == before:
            # nobody the clicker could ship to; don't leave the extra slot dangling
            current_user.max_match_count = current_user.max_match_count - 1
            current_user.save()
    return redirect(url_for('admin.index'))


@app.route('/store-gift-comments', methods=['POST'])
@login_required
def store_gift_comments():
    d = request.json
    current_user.gift_comments = d['giftComments']
    current_user.ship_internationally = d['shipInternationally']
    current_user.country = d['country']
    if 'receivedGift' in d:
        current_user.received_gift = d['receivedGift']
    current_user.save()
    return "success"


@app.route('/store-address', methods=['POST'])
@login_required
def store_address():
    data = request.json
    match = [m for m in current_user.secret_santa_mapping if m.is_active][0]
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


def find_or_create_user(user_data):
    """Look users up by their stable Discord id; fall back to username for accounts from before we stored ids."""
    discord_id = str(user_data['id'])
    user = User.get_or_none(User.discord_id == discord_id)
    if user is None:
        user, _ = User.get_or_create(discord_username=user_data['username'])
        user.discord_id = discord_id
    else:
        user.discord_username = user_data['username']
    return user


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

    user = find_or_create_user(user_data)

    # Mark user as active for this year's matching
    user.active_this_year = True
    user.save()

    my_user_login(user, user_data)

    return redirect(url_for('admin.index'))


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('admin.index'))


if __name__ == '__main__':
    app.run(debug=True)
