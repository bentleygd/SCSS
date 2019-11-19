#!/usr/bin/python3
from hashlib import sha256, sha512
from base64 import b64encode
from os import urandom
from csv import DictWriter, DictReader
from re import search
from os.path import exists
from configparser import ConfigParser
from time import time

from bcrypt import checkpw, gensalt, hashpw
from gnupg import GPG

from scssbin.validate import (
    validate_un, validate_pw, validate_userid, validate_api_key
)


# Setting configuration
config = ConfigParser()
config.read('scss.ini')
u_file = config['scss-user']['file']
c_text = config['scss-gpg']['data']


def register_user(username, password, userids):
    """Takes input, bcrypts it, and writes it to a file."""
    if exists(u_file):
        user_file = open(u_file, 'r', encoding='ascii')
        user_check = DictReader(user_file)
        for line in user_check:
            if username == line['username']:
                print('User already exists.  Exiting.')
                exit(1)
        user_file.close()
    else:
        pass
    if validate_un(username):
        # Setting file info.
        f_headers = ['username', 'password', 'userids', 'apikey',
                     'fl_tstamp', 'fl_count']
        if exists(u_file):
            pwd_file = open(u_file, 'a', newline='', encoding='ascii')
            writer = DictWriter(pwd_file, fieldnames=f_headers)
        else:
            pwd_file = open(u_file, 'w', newline='', encoding='ascii')
            writer = DictWriter(pwd_file, fieldnames=f_headers)
            writer.writeheader()
        # Converting input as needed.
        if validate_pw(password):
            pwd = password.encode(encoding='ascii')
            h_pwd = hashpw(b64encode(sha512(pwd).digest()), gensalt())
            apikey = sha256(b64encode(urandom(32))).hexdigest()
        else:
            print('Password does not meet password requirements')
            exit(1)
        # Writing input to file.
        if ',' in userids:
            writer.writerow({
                'username': username,
                'password': h_pwd.decode(encoding='ascii'),
                'userids': userids.split(','),
                'apikey': apikey,
                'fl_tstamp': 'None',
                'fl_count': '0'
                })
        else:
            writer.writerow({
                'username': username,
                'password': h_pwd.decode(encoding='ascii'),
                'userids': [userids],
                'apikey': apikey,
                'fl_tstamp': 'None',
                'fl_count': '0'
                })
        pwd_file.close()
        return apikey
    else:
        print('User name is not in a valid format.')
        exit(1)


def update_pw(username, new_pwd):
    """Updates a user's password."""
    user_data = []
    user_file = open(u_file, 'r', encoding='ascii')
    user_check = DictReader(user_file)
    for row in user_check:
        if username == row['username']:
            pwd = new_pwd.encode(encoding='ascii')
            h_pwd = hashpw(b64encode(sha512(pwd).digest()), gensalt())
            row['password'] = h_pwd.decode(encoding='ascii')
        user_data.append(row)
    user_file.close()
    user_file_update = open(u_file, 'w', newline='', encoding='ascii')
    f_names = ['username', 'password', 'userids', 'apikey',
               'fl_tstamp', 'fl_count']
    writer = DictWriter(user_file_update, fieldnames=f_names)
    writer.writeheader()
    for entry in user_data:
        writer.writerow(entry)
    user_file_update.close()


def update_api_key(username):
    """Updates a user's API key."""
    user_data = []
    user_file = open(u_file, 'r', encoding='ascii')
    user_check = DictReader(user_file)
    for row in user_check:
        if username == row['username']:
            apikey = sha256(b64encode(urandom(32))).hexdigest()
            row['apikey'] = apikey
        user_data.append(row)
    user_file.close()
    user_file_update = open(u_file, 'w', newline='', encoding='ascii')
    f_names = ['username', 'password', 'userids', 'apikey',
               'fl_tstamp', 'fl_count']
    writer = DictWriter(user_file_update, fieldnames=f_names)
    writer.writeheader()
    for entry in user_data:
        writer.writerow(entry)
    user_file_update.close()
    return apikey


def check_pw(username, password):
    """Returns true if bcrypted password matches."""
    pwd_file = open(u_file, 'r', encoding='ascii')
    reader = DictReader(pwd_file)
    if validate_un(username) and validate_pw(password):
        for row in reader:
            if username == row['username'] and int(row['fl_count']) >= 10:
                return False
            if username == row['username'] and int(row['fl_count']) < 10:
                pwd_hash = row['password'].encode(encoding='ascii')
                pwd = password.encode(encoding='ascii')
                pwd = b64encode(sha512(pwd).digest())
                if checkpw(pwd, pwd_hash):
                    pwd_file.close()
                    return True
                else:
                    pwd_file.close()
                    return False
    else:
        return False


def fail_login(username):
    pwd_file = open(u_file, 'r', encoding='ascii')
    user_data = []
    reader = DictReader(pwd_file)
    for row in reader:
        if username == row['username']:
            if row['fl_tstamp'] != 'None':
                current = time()
                elapsed = current - float(row['fl_tstamp'])
                if elapsed <= 3600:
                    fail_count = int(row['fl_count'])
                    fail_count += 1
                    row['fl_tstamp'] = str(current)
                    row['fl_count'] = str(fail_count)
                else:
                    row['fl_tstamp'] = str(current)
                    row['fl_count'] = '1'
            else:
                row['fl_tstamp'] = str(time())
                row['fl_count'] = '1'
        user_data.append(row)
    pwd_file.close()
    pwd_file = open(u_file, 'w', newline='', encoding='ascii')
    f_names = ['username', 'password', 'userids', 'apikey',
               'fl_tstamp', 'fl_count']
    writer = DictWriter(pwd_file, fieldnames=f_names)
    writer.writeheader()
    for entry in user_data:
        writer.writerow(entry)
    pwd_file.close()
    return 'Authentication failed.'


def fail_api_login(apikey):
    pwd_file = open(u_file, 'r', encoding='ascii')
    user_data = []
    reader = DictReader(pwd_file)
    for row in reader:
        if apikey == row['apikey']:
            if row['fl_tstamp'] != 'None':
                current = time()
                elapsed = current - float(row['fl_tstamp'])
                if elapsed <= 3600:
                    fail_count = int(row['fl_count'])
                    fail_count += 1
                    row['fl_tstamp'] = str(current)
                    row['fl_count'] = str(fail_count)
                else:
                    row['fl_tstamp'] = str(current)
                    row['fl_count'] = '1'
            else:
                row['fl_tstamp'] = str(time())
                row['fl_count'] = '1'
        user_data.append(row)
    pwd_file.close()
    pwd_file = open(u_file, 'w', newline='', encoding='ascii')
    f_names = ['username', 'password', 'userids', 'apikey',
               'fl_tstamp', 'fl_count']
    writer = DictWriter(pwd_file, fieldnames=f_names)
    writer.writeheader()
    for entry in user_data:
        writer.writerow(entry)
    pwd_file.close()
    return 'API unauthorized.'


def good_login(username):
    pwd_file = open(u_file, 'r', encoding='ascii')
    user_data = []
    reader = DictReader(pwd_file)
    for row in reader:
        if username == row['username'] and int(row['fl_count']) > 0:
            row['fl_tstamp'] = 'None'
            row['fl_count'] = '0'
        user_data.append(row)
    pwd_file.close()
    pwd_file = open(u_file, 'w', newline='', encoding='ascii')
    f_names = ['username', 'password', 'userids', 'apikey',
               'fl_tstamp', 'fl_count']
    writer = DictWriter(pwd_file, fieldnames=f_names)
    writer.writeheader()
    for entry in user_data:
        writer.writerow(entry)
    pwd_file.close()


def get_api_key(username, loginstatus):
    if loginstatus:
        pwd_file = open(u_file, 'r', encoding='ascii')
        reader = DictReader(pwd_file)
        for row in reader:
            if username == row['username'] and loginstatus:
                return row['apikey']
        pwd_file.close()
    else:
        return 1


def check_api_key(key):
    """Returns true if valid API key."""
    pwd_file = open(u_file, 'r', encoding='ascii')
    reader = DictReader(pwd_file)
    if validate_api_key(key):
        for row in reader:
            if key == row['apikey']:
                return True
        else:
            return False
    else:
        return 1


def check_userid(apistatus, key, userid):
    """Returns true if user can access coressponding user id."""
    if apistatus:
        pwd_file = open(u_file, 'r', encoding='ascii')
        reader = DictReader(pwd_file)
        for row in reader:
            if key == row['apikey']:
                userids = row['userids']
                if userid in userids and validate_userid(userid):
                    return True
                else:
                    return False
            else:
                print('userid not in password file.')


def get_gpg_pwd(apistatus, userid_status, userid, g_home, g_pass):
    """Returns gpg password if all inputs are valid."""
    if not validate_userid(userid):
        return 'Invalid userid'
    if apistatus and userid_status:
        gpg_file = open(c_text, 'r', encoding='ascii').read().strip('\n')
        g = GPG(homedir=g_home)
        gpg_data = str(g.decrypt(gpg_file, passphrase=g_pass)).split('\n')
        for line in gpg_data:
            reg_search = search(r'(^' + userid + ': )(.+)', line)
            if reg_search:
                return reg_search.group(2)
        else:
            gpg_file.close()
            print('Unable to locate GPG userid.')
