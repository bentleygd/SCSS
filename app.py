#!/usr/bin/python3
from flask import Flask, request, abort

import scssbin

app = Flask(__name__)
@app.route('/getAPI', methods=['POST'])
def get_api():
    if (request.headers.has_key('username') and
            request.headers.has_key('password')):
        user = request.headers.get('username', type=str)
        passwd = request.headers.get('password', type=str)
    else:
        abort(401)
    api = scssbin.get_api_key(user, scssbin.check_pw(user, passwd))
    if api != 1:
        return {'apikey': api}
    else:
        abort(403)
