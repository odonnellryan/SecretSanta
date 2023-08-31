from flask import Flask, redirect, url_for, request, flash
from flask_admin import Admin, expose, BaseView, AdminIndexView
from flask_admin.contrib.peewee import ModelView
from flask_admin.menu import MenuLink
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
import requests
import config
from models import initialize_database, User

app = Flask(__name__)
app.secret_key = config.SECRET_KEY

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)

app.config['FLASK_ADMIN_SWATCH'] = 'superhero'
initialize_database(app)


class HomeView(AdminIndexView):

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login.index'))

    def is_accessible(self):
        return current_user.is_authenticated

    @expose('/')
    def index(self):
        return self.render('index.html')


class LoginView(BaseView):

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('admin.index'))

    def is_accessible(self):
        return not current_user.is_authenticated

    @expose('/')
    def index(self):
        return self.render('login.html')


admin = Admin(app,
              index_view=HomeView(
                  name='SecretSanta', url='/'
              ), template_mode='bootstrap3'
              )


class LoginMenuLink(MenuLink):

    def is_accessible(self):
        return not current_user.is_authenticated


class LogoutMenuLink(MenuLink):

    def is_accessible(self):
        return current_user.is_authenticated


admin.add_view(LoginView(name='Login', url="/login"))
admin.add_link(LogoutMenuLink(name='Logout', category='', url="/logout"))


# admin.add_link(LoginMenuLink(name='Login', category='', url="/login"))


class MyModelView(ModelView):

    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login.index'))


admin.add_view(MyModelView(User))


@login_manager.user_loader
def load_user(user_id):
    user = User.get(id=user_id)
    return user


@app.route('/login-with-discord')
def login_with_discord():
    discord_auth_url = f"https://discord.com/api/oauth2/authorize?client_id={config.DISCORD_APP_ID}&redirect_uri={config.DISCORD_REDIRECT_URI}&response_type=code&scope=identify"
    return redirect(discord_auth_url)


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
        discord_id=str(user_data['id']),
        defaults={
            'discord_username': user_data['username']
        }
    )

    login_user(user)

    return redirect(url_for('admin.index'))


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('admin.index'))


@app.route('/test-dm')
def test_dm():
    channel = requests.post('https://discord.com/api/users/@me/channels', json={
        'recipient_id': '302576532814036992'
    }, headers={
        'Authorization': f'Bot {config.DISCORD_BOT_TOKEN}'
    })
    channel_id = channel.json()['id']
    message = requests.post(f'https://discord.com/api/channels/{channel_id}/messages', json={
        'content': 'This is a test!'
    }, headers={
        'Authorization': f'Bot {config.DISCORD_BOT_TOKEN}'
    })
    return redirect(url_for('admin.index'))


if __name__ == '__main__':
    app.run(debug=True)
