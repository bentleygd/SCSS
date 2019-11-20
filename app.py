#!/usr/bin/python3
from flask import Flask, request, abort, make_response, session
from configparser import ConfigParser
from os import urandom
from hashlib import sha256
from base64 import b64encode

from scssbin import scss


# Setting the configuration.
config = ConfigParser()
config.read('scss.ini')
g_home = config['scss-gpg']['gnupghome']
g_file = open(config['scss-gpg']['key'], 'r', encoding='ascii')
g_key = g_file.read()
g_file.close()


app = Flask(__name__)
app.secret_key = sha256(b64encode(urandom(32))).digest()
# Uncomment the below line on a SSL enabled server.
# app.config['SESSION_COOKIE_SECURE'] = True
@app.route('/', methods=['GET'])
def index():
    response = make_response('Not here', 302)
    response.headers['Location'] = (
        'https://www.youtube.com/watch?v=HEXWRTEbj1I'
    )
    return response


@app.route('/getAPI', methods=['POST'])
def get_api():
    if 'failed_login' in session:
        if session.get('failed_login') >= 6:
            abort(403)
    else:
        session['failed_login'] = 0
    if 'username' in request.headers and 'password' in request.headers:
        user = request.headers.get('username', type=str)
        passwd = request.headers.get('password', type=str)
    else:
        abort(400)
    api = scss.get_api_key(user, scss.check_pw(user, passwd))
    if api:
        scss.good_login(user)
        return {'apikey': api}
    else:
        session['failed_login'] += 1
        scss.fail_login(user)
        abort(401)


@app.route('/getGPG', methods=['POST'])
def get_gpg_pass():
    if 'failed_login' in session:
        if session.get('failed_login') >= 6:
            abort(403)
    else:
        session['failed_login'] = 0
    if 'failed_uid' in session:
        if session['failed_uid'] >= 6:
            abort(403)
    else:
        session['failed_uid'] = 0
    if 'api-key' in request.headers and 'userid' in request.headers:
        api_key = request.headers.get('api_key', type=str)
        userid = request.headers.get('userid', type=str)
    else:
        abort(400)
    auth = scss.check_api_key(api_key)
    uid_chck = scss.check_userid(auth, api_key, userid)
    if auth:
        if uid_chck:
            gpg_pass = scss.get_gpg_pwd(auth, uid_chck, userid, g_home, g_key)
            if gpg_pass == 1:
                response = make_response('Invalid User ID', 400)
                response.headers['Error'] = ('Invalid User ID')
                return response
            else:
                return {'gpg_pass': gpg_pass}
        else:
            scss.fail_api_login(api_key)
            session['failed_uid'] += 1
            abort(403)
    else:
        session['failed_login'] += 1
        abort(403)
