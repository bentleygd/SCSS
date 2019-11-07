#!/usr/bin/python3
from flask import Flask, request, abort

import scssbin


g_key = input('Key> ')

app = Flask(__name__)
@app.route('/getAPI', methods=['POST'])
def get_api():
    if ('username' in request.headers and
        'password' in request.headers and
            request.headers.get('User-Agent',  type=str) == 'scss-client'):
        user = request.headers.get('username', type=str)
        passwd = request.headers.get('password', type=str)
    else:
        abort(400)
    api = scssbin.get_api_key(user, scssbin.check_pw(user, passwd))
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
    auth = scssbin.check_api_key(user, api_key)
    if auth:
        gpg_pass = scssbin.get_gpg_pwd(auth, userid, g_home, g_key)
        return {'gpg_pass': gpg_pass}
    else:
        abort(403)
