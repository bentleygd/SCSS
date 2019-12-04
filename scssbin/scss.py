#!/usr/bin/python3
from hashlib import sha256, sha512
from base64 import b64encode, b32encode
from os import urandom
from csv import DictWriter, DictReader
from re import search
from os.path import exists
from configparser import ConfigParser
from time import time
from sys import stderr

from bcrypt import checkpw, gensalt, hashpw
from gnupg import GPG
from pyotp import TOTP

from scssbin.validate import (
    validate_un, validate_pw, validate_userid, validate_api_key,
    validate_totp
)


# Setting configuration
config = ConfigParser()
try:
    config.read('scss.ini')
except PermissionError:
    print(
        'ERROR: Unable to open configuration due to permissions.',
        file=stderr
    )
except FileNotFoundError:
    print(
        'ERROR: Unable to locate the specified configuration file.',
        file=stderr
    )
try:
    u_file = config['scss-user']['file']
    c_text = config['scss-gpg']['data']
except KeyError:
    print('ERROR: Unable to read configuration file.')


def register_user(username, password, userids):
    """Takes input, bcrypts it, and writes it to a file.

    Keyword arguments:
    username - The unique identifier for the user.
    password - Self-explanatory.
    userids - The unique identifiers that the user will have access to
    in order to retrieve encrypted data.

    Outupt:
    The function writes the username, hashed password, userids, a TOTP
    key and a generated API key to u_file as specified in the
    configuration above.
    """
    if exists(u_file):
        try:
            user_file = open(u_file, 'r', encoding='ascii')
        except PermissionError:
            print('Unable to open the file.  Check permissions.')
            exit(1)
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
        f_headers = ['username', 'password', 'userids', 'apikey', 'totp',
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
            totp = b32encode(urandom(16)).decode('ascii').strip('=')
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
                'topt': totp,
                'fl_tstamp': 'None',
                'fl_count': '0'
                })
        else:
            writer.writerow({
                'username': username,
                'password': h_pwd.decode(encoding='ascii'),
                'userids': [userids],
                'apikey': apikey,
                'totp': totp,
                'fl_tstamp': 'None',
                'fl_count': '0'
                })
        pwd_file.close()
        return {'apikey': apikey, 'totp': totp}
    else:
        print('User name is not in a valid format.')
        exit(1)


def update_pw(username, new_pwd):
    """Updates a user's password.

    Keyword arguments:
    username - The unique identifier for the user.
    new_pwd - The user's new password.

    Outputs:
    This function updates the user's password hash in the file noted in
    the configuration.

    Raises:
    PermissionError - Self explanatory.
    FileNotFoundError - Self explanatory."""
    user_data = []
    try:
        user_file = open(u_file, 'r', encoding='ascii')
    except FileNotFoundError:
        print('Unable to locate file.  Check the configuration.')
        exit(1)
    except PermissionError:
        print('Unable to open the file.  Check permissions.')
        exit(1)
    user_check = DictReader(user_file)
    # Searching for, and updating, the user's record.
    for row in user_check:
        if username == row['username']:
            pwd = new_pwd.encode(encoding='ascii')
            h_pwd = hashpw(b64encode(sha512(pwd).digest()), gensalt())
            row['password'] = h_pwd.decode(encoding='ascii')
        user_data.append(row)
    user_file.close()
    # Writing the data back into the user file.
    user_file_update = open(u_file, 'w', newline='', encoding='ascii')
    f_names = ['username', 'password', 'userids', 'apikey', 'totp',
               'fl_tstamp', 'fl_count']
    writer = DictWriter(user_file_update, fieldnames=f_names)
    writer.writeheader()
    for entry in user_data:
        writer.writerow(entry)
    user_file_update.close()


def update_api_key(username):
    """Updates a user's API key.

    Keyword arguments:
    username - The unique identifier for the user.

    Outputs:
    This function updates the user's API key in the file noted in
    the configuration.

    Raises:
    PermissionError - Self explanatory.
    FileNotFoundError - Self explanatory."""
    user_data = []
    try:
        user_file = open(u_file, 'r', encoding='ascii')
    except FileNotFoundError:
        print('Unable to locate file.  Check the configuration.')
        exit(1)
    except PermissionError:
        print('Unable to open the file.  Check permissions.')
        exit(1)
    user_check = DictReader(user_file)
    # Searching for, and updating, the user's record.
    for row in user_check:
        if username == row['username']:
            apikey = sha256(b64encode(urandom(32))).hexdigest()
            row['apikey'] = apikey
        user_data.append(row)
    user_file.close()
    # Writing the new data back into the file.
    user_file_update = open(u_file, 'w', newline='', encoding='ascii')
    f_names = ['username', 'password', 'userids', 'apikey', 'totp',
               'fl_tstamp', 'fl_count']
    writer = DictWriter(user_file_update, fieldnames=f_names)
    writer.writeheader()
    for entry in user_data:
        writer.writerow(entry)
    user_file_update.close()
    return apikey


def check_pw(username, password):
    """Returns true if bcrypted password matches provided input.

    Keyword arguments:
    username - The unique identifier for the user.
    password - Self-explanatory.

    Output:
    Returns a status based on the outcome of determining whether or not
    the provided password matches what is in the user file.  If the
    password matches, it returns True.  If it does not match, it
    returns False."""
    pwd_file = open(u_file, 'r', encoding='ascii')
    reader = DictReader(pwd_file)
    # Performing input validation.
    if validate_un(username) and validate_pw(password):
        for row in reader:
            # Checking to see if the account is locked out.
            if username == row['username'] and int(row['fl_count']) <= 9:
                pwd_hash = row['password'].encode(encoding='ascii')
                pwd = password.encode(encoding='ascii')
                pwd = b64encode(sha512(pwd).digest())
                # Performing the password hash comparison.
                if checkpw(pwd, pwd_hash):
                    pwd_file.close()
                    return True
                else:
                    pwd_file.close()
                    return False
            else:
                pwd_file.close()
                return False
    else:
        return False


def fail_login(username):
    """Writes a failed login counter to a file.

    Keyword arguments:
    username - The unique identifier for the user.

    Outputs:
    Writes an numeric value to a file that indicates how many times a
    given username has failed at the authentication process."""
    pwd_file = open(u_file, 'r', encoding='ascii')
    user_data = []
    reader = DictReader(pwd_file)
    for row in reader:
        if username == row['username']:
            # Checking to see when the last failed login occurred.
            if row['fl_tstamp'] != 'None':
                current = time()
                elapsed = current - float(row['fl_tstamp'])
                if elapsed <= 3600:
                    # If a failed login occured within the past hour,
                    # increment by one.
                    fail_count = int(row['fl_count'])
                    fail_count += 1
                    row['fl_tstamp'] = str(current)
                    row['fl_count'] = str(fail_count)
                else:
                    # If a failed login has occured in the past but
                    # not occured within the past hour, set counter to
                    # one.
                    row['fl_tstamp'] = str(current)
                    row['fl_count'] = '1'
            else:
                # If a failed login has not occurred in the past hour,
                # record the current timestamp and set the counter to
                # one.
                row['fl_tstamp'] = str(time())
                row['fl_count'] = '1'
        user_data.append(row)
    pwd_file.close()
    pwd_file = open(u_file, 'w', newline='', encoding='ascii')
    f_names = ['username', 'password', 'userids', 'apikey', 'totp',
               'fl_tstamp', 'fl_count']
    writer = DictWriter(pwd_file, fieldnames=f_names)
    writer.writeheader()
    for entry in user_data:
        writer.writerow(entry)
    pwd_file.close()
    return 'Authentication failed.'


def fail_api_login(apikey):
    """Writes a failed login counter to a file.

    Keyword arguments:
    apikey - The unique apikey for the user.

    Outputs:
    Writes an numeric value to a file that indicates how many times a
    given apikey has failed at the userid authorization process."""
    pwd_file = open(u_file, 'r', encoding='ascii')
    user_data = []
    reader = DictReader(pwd_file)
    for row in reader:
        if apikey == row['apikey']:
            # Checking to see when the last failed login occurred.
            if row['fl_tstamp'] != 'None':
                current = time()
                elapsed = current - float(row['fl_tstamp'])
                if elapsed <= 3600:
                    # If a failed login occured within the past hour,
                    # increment by one.
                    fail_count = int(row['fl_count'])
                    fail_count += 1
                    row['fl_tstamp'] = str(current)
                    row['fl_count'] = str(fail_count)
                else:
                    # If a failed login has occured in the past but
                    # not occured within the past hour, set counter to
                    # one.
                    row['fl_tstamp'] = str(current)
                    row['fl_count'] = '1'
            else:
                # If a failed login has not occurred in the past hour,
                # record the current timestamp and set the counter to
                # one.
                row['fl_tstamp'] = str(time())
                row['fl_count'] = '1'
        user_data.append(row)
    pwd_file.close()
    # Writing the new data back into the file.
    pwd_file = open(u_file, 'w', newline='', encoding='ascii')
    f_names = ['username', 'password', 'userids', 'apikey', 'totp'
               'fl_tstamp', 'fl_count']
    writer = DictWriter(pwd_file, fieldnames=f_names)
    writer.writeheader()
    for entry in user_data:
        writer.writerow(entry)
    pwd_file.close()


def map_api_to_user(apikey):
    """Returns the username associated with a given API key.

    Keyword arguments:
    apikey - The unique apikey for the user.

    Output:
    Returns the username associated with a given API keys so that logs
    for failed API events are correctly associated to a user."""
    pwd_file = open(u_file, 'r', encoding='ascii')
    reader = DictReader(pwd_file)
    for row in reader:
        if apikey == row['apikey']:
            return row['username']
        else:
            return 'Unknown'
    pwd_file.close()


def good_login(username):
    """Updates a user's record when a succesful login occurs.

    Keyword arguments:
    username - The unique identifier for the user.

    Outputs:
    Overwrites the failed login numeric value to 0 to avoid locking a
    user's account for user error (instead of a brute force attack).
    """
    pwd_file = open(u_file, 'r', encoding='ascii')
    user_data = []
    reader = DictReader(pwd_file)
    for row in reader:
        # Checking to see if a failed login has occured in the past.
        if username == row['username'] and int(row['fl_count']) > 0:
            # If it has, reset the counters.
            row['fl_tstamp'] = 'None'
            row['fl_count'] = '0'
        user_data.append(row)
    pwd_file.close()
    # Writing the new data back into the file.
    pwd_file = open(u_file, 'w', newline='', encoding='ascii')
    f_names = ['username', 'password', 'userids', 'apikey', 'totp',
               'fl_tstamp', 'fl_count']
    writer = DictWriter(pwd_file, fieldnames=f_names)
    writer.writeheader()
    for entry in user_data:
        writer.writerow(entry)
    pwd_file.close()


def get_api_key(username, loginstatus):
    """Takes username and true/false status of login, returns API key.

    Keyword arguments:
    username - The unique identifier for the user.
    loginstatus - The true/false status of the login.  This should be
    the returned value of the check_pw function.

    Output:
    The function returns' a given user's API key."""
    # Checking to make sure the user succesfully authenticated.
    if loginstatus:
        pwd_file = open(u_file, 'r', encoding='ascii')
        reader = DictReader(pwd_file)
        # Getting the user's API key.
        for row in reader:
            if username == row['username'] and loginstatus:
                return row['apikey']
        pwd_file.close()
    else:
        return False


def check_api_key(key):
    """Returns true if input is a valid API key.

    Keyword arugments:
    key - A user's API key.

    Output:
    The function returns true if the API key provided is valid."""
    pwd_file = open(u_file, 'r', encoding='ascii')
    reader = DictReader(pwd_file)
    # Performing input validation.
    if validate_api_key(key):
        for row in reader:
            # Checking the API key.
            if key == row['apikey'] and int(row['fl_count']) <= 9:
                return True
    else:
        return False


def check_totp(totp, key):
    """Retruns true if totp is a valid TOTP

    Key word arguments:
    totp - The six digits provided by a TOTP app or function.
    key - API key.

    Output:
    Bool value based on whether or not the six_digits are the valid
    TOTP for the 30 second window."""
    pwd_file = open(u_file, 'r', encoding='ascii')
    reader = DictReader(pwd_file)
    # Performing input validation.
    if validate_totp(totp) and validate_api_key(key):
        for row in reader:
            # Checking the TOTP value
            if key == row['apikey'] and int(row['fl_count']) <= 9:
                MFA = TOTP(row['totp'])
                if MFA.verify(totp):
                    return True
                else:
                    return False
    else:
        return False


def check_userid(apistatus, key, userid):
    """Returns true if user can access coressponding user id.

    Keyword arugments:
    apitstatus - The true/false return value from the check_api_key
    function.
    key - The user's API key.
    userid - The userid that corresponds (key:value) to sensitive data
    that is being retrieved.

    Output:
    The function returns true if the provided API key is permitted to
    access the provided userid."""
    # Checking to see if the API key is valid.
    if apistatus:
        pwd_file = open(u_file, 'r', encoding='ascii')
        reader = DictReader(pwd_file)
        for row in reader:
            # Checking to see if the API key has access to the userid.
            if key == row['apikey']:
                userids = row['userids']
                if userid in userids and validate_userid(userid):
                    return True
                else:
                    return False
    else:
        return False


def get_gpg_pwd(apistatus, userid_status, mfa, userid, g_home, g_pass):
    """Returns gpg password if all inputs are valid.

    Keyword arguments:
    apistatus - The true/false return value from the check_api_key
    function.
    userid_stauts - The true/false return value from the check_userid
    function.
    mfa - The true/false return value from the check_totp
    function.
    userid -  The userid that corresponds (key:value) to sensitive data
    that is being retrieved.
    g_home - The GPG home directory for this application, i.e.
    export |grep GNUPGHOME.
    g_pass - The password for the GPG private key.

    Output:
    The function returns the sensitive data that corresponds to the
    userid."""
    # Performing input validation.
    if not validate_userid(userid):
        return 1
    # Checking login status and that the API key is authorized to
    # access the userid.
    if apistatus and userid_status and mfa:
        gpg_file = open(c_text, 'r', encoding='ascii').read().strip('\n')
        g = GPG(homedir=g_home)
        gpg_data = str(g.decrypt(gpg_file, passphrase=g_pass)).split('\n')
        for line in gpg_data:
            reg_search = search(r'(^' + userid + ': )(.+)', line)
            if reg_search:
                return reg_search.group(2)
        gpg_file.close()
    else:
        return False
