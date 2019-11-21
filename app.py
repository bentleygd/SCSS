#!/usr/bin/python3
from flask import Flask, request, abort, make_response, session
from configparser import ConfigParser
from os import urandom
from hashlib import sha256
from base64 import b64encode
from logging.config import dictConfig

from scssbin import scss


# Setting the configuration.
config = ConfigParser()
config.read('scss.ini')
g_home = config['scss-gpg']['gnupghome']
g_file = open(config['scss-gpg']['key'], 'r', encoding='ascii')
g_key = g_file.read()
g_file.close()

# Settting logging configuration.
dictConfig({
    'version': 1,
    'formatters': {'default': {
        'format': '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
    }},
    'handlers': {'wsgi': {
        'class': 'logging.StreamHandler',
        'stream': 'ext://flask.logging.wsgi_errors_stream',
        'formatter': 'default'
    }},
    'root': {
        'level': 'INFO',
        'handlers': ['wsgi']
    }
})

# Application config
app = Flask(__name__)
app.secret_key = sha256(b64encode(urandom(32))).digest()
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
# Uncomment the below line on a SSL enabled server.
# app.config['SESSION_COOKIE_SECURE'] = True
@app.route('/', methods=['GET'])
def index():
    response = make_response('Not here', 302)
    response.headers['Location'] = (
        'https://www.youtube.com/watch?v=HEXWRTEbj1I'
    )
    return response


# Endpoint that allows for API key retrieval with UN/PW.
@app.route('/getAPI', methods=['POST'])
def get_api():
    # Checking session cookie.
    if 'failed_login' in session:
        if session.get('failed_login') >= 6:
            user = request.headers.get('username', type=str)
            app.logger.warn('%s has been banned via session cookie.', user)
            abort(403)
    else:
        session['failed_login'] = 0
    # Checking submitted headers.
    if 'username' in request.headers and 'password' in request.headers:
        user = request.headers.get('username', type=str)
        passwd = request.headers.get('password', type=str)
    else:
        app.logger.debug('Invalid HTTP request for API key retrieval.')
        abort(400)
    # Checking user credentials.
    api = scss.get_api_key(user, scss.check_pw(user, passwd))
    if api:
        scss.good_login(user)
        app.logger.info('%s logged in succesfully, retrieved API key.', user)
        return {'apikey': api}
    else:
        session['failed_login'] += 1
        app.logger.info('%s failed to log in.', user)
        scss.fail_login(user)
        abort(401)


# Endpoint that allows for retrieval of encrypted things using an API
# key as an authentication method.
@app.route('/getGPG', methods=['POST'])
def get_gpg_pass():
    # Checking session cookie.
    if 'failed_login' in session:
        if session.get('failed_login') >= 6:
            app.logger.warn('Banned session cookie vault access attempt.')
            abort(403)
    else:
        session['failed_login'] = 0
    if 'failed_uid' in session:
        if session['failed_uid'] >= 6:
            userid = request.headers.get('userid', type=str)
            app.logger.warn(
                'Banned session cookie attempt to access %s.', userid
                )
            abort(403)
    else:
        session['failed_uid'] = 0
    # Checking headers.
    if 'api-key' in request.headers and 'userid' in request.headers:
        api_key = request.headers.get('api_key', type=str)
        userid = request.headers.get('userid', type=str)
    else:
        app.logger.debug('Invalid HTTP request for vault access.')
        abort(400)
    # Validating login and userid access.
    auth = scss.check_api_key(api_key)
    uid_chck = scss.check_userid(auth, api_key, userid)
    if auth:
        if uid_chck:
            # Retrieving encrypted data if authorization passes.
            gpg_pass = scss.get_gpg_pwd(auth, uid_chck, userid, g_home, g_key)
            if gpg_pass == 1:
                response = make_response('Invalid User ID', 400)
                response.headers['Error'] = ('Invalid User ID')
                return response
            else:
                app.logger.info('%s data retrieved from valult.', userid)
                return {'gpg_pass': gpg_pass}
        else:
            scss.fail_api_login(api_key)
            session['failed_uid'] += 1
            app.logger.info('Failed vault access atttempt for %s.', userid)
            abort(403)
    else:
        app.logger.info('Failed vault API login.')
        session['failed_login'] += 1
        abort(403)
