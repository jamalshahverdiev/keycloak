from logging import Formatter, INFO
from logging.handlers import RotatingFileHandler
from flask import Flask, redirect, url_for, session, render_template, request
from functools import wraps
from authlib.integrations.flask_client import OAuth
from urllib.parse import urlencode
from time import time
from datetime import datetime, timedelta
from os import urandom, getenv

app = Flask(__name__)
app.secret_key = getenv('FLASK_APP_SECRET_KEY')  
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30) 
oauth = OAuth(app)

keycloak_client = oauth.create_client('keycloak')  
keycloak = oauth.register(
    name='keycloak',
    client_id=getenv('KEYCLOAK_CLIENT_ID'),
    client_secret=getenv('KEYCLOAK_CLIENT_SECRET'),
    server_metadata_url=getenv('KEYCLOAK_SERVER_METADATA_URL'),
    client_kwargs={
        'scope': 'openid profile email roles',
    }
)

def role_required(required_role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user_info = session.get('user_info')
            if not user_info:
                return redirect(url_for('login', next=request.url))
            user_roles = user_info.get('realm_access', {}).get('roles', [])

            if required_role not in user_roles:
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def setup_logging():
    log_formatter = Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    handler = RotatingFileHandler('app.log', maxBytes=1000000, backupCount=10)
    handler.setFormatter(log_formatter)
    handler.setLevel(INFO)
    app.logger.addHandler(handler)
    app.logger.setLevel(INFO)

setup_logging()

def generate_nonce(length=16):
    return urandom(length).hex()

def is_token_expired(token_info):
    if 'expires_at' in token_info:  
        expires_at = datetime.fromtimestamp(token_info['expires_at'])
        return datetime.utcnow() >= expires_at
    return True  

def refresh_access_token_if_needed():
    token_info = session.get('keycloak_token')
    if token_info and is_token_expired(token_info):
        app.logger.info('Access token has expired, refreshing it.')
        try:
            refreshed_token_info = keycloak.refresh_token(token_info['refresh_token'])
            session['keycloak_token'] = refreshed_token_info
            session['keycloak_token']['expires_at'] = int(time()) + refreshed_token_info['expires_in']
        except Exception as e:
            app.logger.exception('Error while refreshing access token: %s', e)
            return redirect(url_for('logout'))

@app.before_request
def before_request():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=30)
    session.modified = True

    if 'keycloak_token' not in session and request.endpoint not in ['login', 'logout', 'index', 'authorized']:
        app.logger.info('Session expired or not present.')
        return redirect(url_for('login'))
    
@app.route('/')
def index():
    app.logger.info('Root URL accessed')
    return render_template('login.html')

@app.route('/home')
def home():
    refresh_access_token_if_needed() 
    user_info = session.get('user_info')
    if user_info:
        app.logger.info('User accessed home page: %s', user_info.get('preferred_username', ''))
        return render_template('home.html', username=user_info.get('preferred_username', ''))
    app.logger.info('Unauthorized access attempt to home page.')
    return redirect(url_for('login'))

@app.route('/login')
def login():
    app.logger.info('User attempting to login')
    session.clear()

    nonce = generate_nonce()
    session['nonce'] = nonce
    
    redirect_uri = url_for('authorized', _external=True)
    return keycloak.authorize_redirect(redirect_uri, nonce=nonce)

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    app.logger.info('User requested logout')
    token = session.pop('keycloak_token', None)
    session.pop('user_info', None)
    session.pop('nonce', None)
    
    if token:
        app.logger.info('Processing logout with token')
        keycloak_metadata = keycloak.load_server_metadata()
        keycloak_issuer = keycloak_metadata.get('issuer')

        if keycloak_issuer is None:
            app.logger.error('Keycloak issuer URL not found in server metadata.')
            return redirect(url_for('index'))

        # Construct the Keycloak logout URL
        keycloak_logout_url = f'{keycloak_issuer}/protocol/openid-connect/logout'

        post_logout_redirect_uri = url_for('index', _external=True)

        params = {
            'post_logout_redirect_uri': post_logout_redirect_uri,
            'id_token_hint': token['id_token']  
        }

        logout_url_with_redirect = f'{keycloak_logout_url}?{urlencode(params)}'
        app.logger.info('Redirecting to Keycloak logout URL.')
        return redirect(logout_url_with_redirect)
    else:
        app.logger.info('Logout requested without active session token.')
        return redirect(url_for('index'))

@app.route('/login/authorized')
def authorized():
    app.logger.info('Processing authorization callback.')
    nonce = session.get('nonce')
    try:
        token = keycloak.authorize_access_token()
        session['keycloak_token'] = token
        
        access_token_expires_at = token.get('expires_at', 0)
        refresh_token_expires_at = token.get('refresh_expires_in', 0) + int(time())
        user_info = keycloak.parse_id_token(token, nonce)
        print(f"User info: {user_info}")
        user_roles = user_info.get('realm_access', {}).get('roles', [])
        print(f"User roles: {user_roles}")
        # Make sure that user has either 'Admin' or 'Viewer' role
        if 'Admin' in user_roles:
            user_role = 'Admin'
        elif 'Viewer' in user_roles:
            user_role = 'Viewer'
        else:
            app.logger.error('User role is not valid or not assigned.')
            return redirect(url_for('logout'))
        
        # Store the user info and roles in session
        session['user_info'] = user_info
        session['user_info']['role'] = user_role

        # Logging the expiration times
        access_token_expires_at_readable = datetime.utcfromtimestamp(access_token_expires_at).strftime('%Y-%m-%d %H:%M:%S UTC')
        refresh_token_expires_at_readable = datetime.utcfromtimestamp(refresh_token_expires_at).strftime('%Y-%m-%d %H:%M:%S UTC')
        session['access_token_expires_at'] = access_token_expires_at_readable
        session['refresh_token_expires_at'] = refresh_token_expires_at_readable
        app.logger.info('User authorized successfully. Role: %s, Access token expires: %s, Refresh token expires: %s', user_role, access_token_expires_at_readable, refresh_token_expires_at_readable)
        
        # Redirect based on role
        if user_role == 'Admin':
            return redirect(url_for('admin_page'))
        else:
            return redirect(url_for('home'))

    except Exception as e:
        app.logger.exception('Error during authorization callback: %s', e)
        return redirect(url_for('index'))

@app.route('/admin')
@role_required('Admin')
def admin_page():
    user_info = session.get('user_info')
    username = user_info.get('preferred_username') if user_info else 'Guest'
    return render_template('admin.html', username=username)

@app.route('/restricted')
@role_required('Admin')
def restricted_page():
    user_info = session.get('user_info')
    username = user_info.get('preferred_username') if user_info else 'Guest'
    return render_template('restricted.html', username=username)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)
