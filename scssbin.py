#!/usr/bin/python3
from hashlib import sha256
from base64 import b64encode
from os import urandom
from csv import DictWriter, DictReader
from re import search
from os.path import exists

from bcrypt import checkpw, gensalt, hashpw
from gnupg import GPG

from validate import validate_un


def regsiter_user(username, password, userids):
    """Takes input, bcrypts it, and writes it to a file."""
    if exists('scss_users.csv'):
        user_file = open('scss_users.csv', 'r', encoding='ascii')
        user_check = DictReader(user_file)
        for line in user_check:
            if username == line['username']:
                return 1
        user_file.close()
    else:
        pass
    if validate_un(username):
        # Setting file info.
        f_headers = ['username', 'password', 'userids', 'apikey']
        if exists('scss_users.csv'):
            pwd_file = open(
                'scss_users.csv', 'a', newline='', encoding='ascii'
                )
        else:
            pwd_file = open(
                'scss_users.csv', 'w', newline='', encoding='ascii'
                )
        writer = DictWriter(pwd_file, fieldnames=f_headers)
        # Converting input as needed.
        pwd = password.encode(encoding='ascii')
        h_pwd = hashpw(b64encode(sha256(pwd).digest()), gensalt())
        apikey = sha256(b64encode(urandom(32))).hexdigest()
        # Writing input to file.
        if ',' in userids:
            writer.writerow({
                'username': username,
                'password': h_pwd.decode(encoding='ascii'),
                'userids': userids.split(','),
                'apikey': apikey
                })
        else:
            writer.writerow({
                'username': username,
                'password': h_pwd.decode(encoding='ascii'),
                'userids': userids,
                'apikey': apikey
                })
        pwd_file.close()
        return apikey
    else:
        print('User name is not in a valid format.')
        exit(1)


def check_pw(username, password):
    """Returns true if bcrypted password matches."""
    pwd_file = open('scss_users.csv', 'r', encoding='ascii')
    reader = DictReader(pwd_file)
    for row in reader:
        if username == row['username']:
            pwd_hash = row['password'].encode(encoding='ascii')
            pwd = password.encode(encoding='ascii')
            pwd = b64encode(sha256(pwd).digest())
            if checkpw(pwd, pwd_hash):
                return True
            else:
                return False


def get_api_key(username, loginstatus):
    if loginstatus:
        pwd_file = open('scss_users.csv', 'r', encoding='ascii')
        reader = DictReader(pwd_file)
        for row in reader:
            if username == row['username']:
                return row['apikey']
        pwd_file.close()
    else:
        return 1


def check_api_key(username, key):
    """Returns true if valid API key."""
    pwd_file = open('scss_users.csv', 'r', encoding='ascii')
    reader = DictReader(pwd_file)
    for row in reader:
        if username == row['username'] and key == row['apikey']:
            return True
        else:
            return False


def check_userid(apistatus, username, userid):
    """Returns true if user can access coressponding user id."""
    if apistatus:
        pwd_file = open('scss_users.csv', 'r', encoding='ascii')
        reader = DictReader(pwd_file)
        for row in reader:
            if username == row['username']:
                userids = row['userids']
                if userid in userids:
                    return True
                else:
                    return False
            else:
                print('userid not in password file.')


def get_gpg_pwd(apistatus, userid, g_home, g_pass):
    """Returns gpg password if all inputs are valid."""
    if apistatus:
        gpg_file = open(
            'scss_storage', 'r', encoding='ascii'
            ).read().strip('\n')
        g = GPG(homedir=g_home)
        gpg_data = g.decrypt(gpg_file, passphrase=g_pass)
        for line in gpg_data:
            reg_search = search(r'(^' + userid + ': )(.+)', line)
            if reg_search:
                return reg_search.group(2)
            else:
                print('Unable to locate GPG userid.')
