#!/usr/bin/python3
from flask import Flask, request, abort, make_response
from configparser import ConfigParser

from scssbin import scss


# Setting the configuration.
config = ConfigParser()
config.read('scss.ini')
g_home = config['scss-gpg']['gnupghome']
g_key = open(config['scss-gpg']['key'], 'r', encoding='ascii').read()

app = Flask(__name__)
@app.route('/', methods=['GET'])
def index():
    response = make_response(302)
    response.headers['Location'] = (
        'https://https://www.youtube.com/watch?v=dQw4w9WgXcQ'
    )


@app.route('/getAPI', methods=['POST'])
def get_api():
    if ('username' in request.headers and
        'password' in request.headers and
            request.headers.get('User-Agent',  type=str) == 'scss-client'):
        user = request.headers.get('username', type=str)
        passwd = request.headers.get('password', type=str)
    else:
        abort(400)
    api = scss.get_api_key(user, scss.check_pw(user, passwd))
    if api != 1:
        return {'apikey': api}
    else:
        abort(401)


@app.route('/getGPG', methods=['POST'])
def get_gpg_pass():
    if ('username' in request.headers and
        'api_key' in request.headers and
        'userid' in request.headers and
            request.headers.get('User-Agent', type=str) == 'sccss-client'):
        user = request.headers.get('username', type=str)
        api_key = request.headers.get('api_key', type=str)
        userid = request.headers.get('userid', type=str)
    else:
        abort(400)
    auth = scss.check_api_key(user, api_key)
    if auth:
        gpg_pass = scss.get_gpg_pwd(auth, userid, g_home, g_key)
        return {'gpg_pass': gpg_pass}
    else:
        abort(403)
