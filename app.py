#!/usr/bin/python3
from flask import Flask, request, abort, make_response
from configparser import ConfigParser

from scssbin import scss


# Setting the configuration.
config = ConfigParser()
config.read('scss.ini')
g_home = config['scss-gpg']['gnupghome']
g_file = open(config['scss-gpg']['key'], 'r', encoding='ascii')
g_key = g_file.read()
g_file.close()


app = Flask(__name__)
@app.route('/', methods=['GET'])
def index():
    response = make_response('Not here', 302)
    response.headers['Location'] = (
        'https://www.youtube.com/watch?v=HEXWRTEbj1I'
    )
    return response


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
        scss.good_login(user)
        return {'apikey': api}
    else:
        scss.fail_login(user)
        abort(401)


@app.route('/getGPG', methods=['POST'])
def get_gpg_pass():
    if ('api-key' in request.headers and
        'userid' in request.headers and
            request.headers.get('User-Agent', type=str) == 'scss-client'):
        api_key = request.headers.get('api_key', type=str)
        userid = request.headers.get('userid', type=str)
    else:
        abort(400)
    auth = scss.check_api_key(api_key)
    uid_chck = scss.check_userid(auth, api_key, userid)
    if auth:
        if uid_chck:
            gpg_pass = scss.get_gpg_pwd(auth, uid_chck, userid, g_home, g_key)
            return {'gpg_pass': gpg_pass}
        else:
            scss.fail_api_login(api_key)
            abort(403)
    elif auth == 1:
        abort(400)
    else:
        abort(403)
