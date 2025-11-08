"""
SQLite DB related functions for the SCSS project.

Created by: Gabriel Bentley
Last Modified by: Gabriel Bentley
Last Modified Date: TBD
"""
from logging import getLogger
from hashlib import sha256, sha512
from base64 import b64encode, b32encode
from secrets import token_bytes
from re import search, escape
from os.path import exists
from time import time
from sys import exit as sys_exit

from sqlcipher3 import dbapi2 as sqlite
from bcrypt import checkpw, gensalt, hashpw
from gnupg import GPG
from pyotp import TOTP

from scssbin.validate import (
    validate_un, validate_pw, validate_userid, validate_api_key,
    validate_totp
)


def scss_db_setup(key, db_name):
    """
    This function creates the SCSS SQLite DB and the tables that will
    be used by the application.

    Required Input:
    key - str(), The encryption key that will be used by SQLCipher to encrypt
    the DB.
    db_name - str(), The file name of the SQLite DB used by SCSS.

    Output:
    TBD

    Exceptions:
    TBD
    """
    # Setting up logging.
    log = getLogger(__name__)
    # Creating the SQLite DB.
    scss_db = sqlite.connect(db_name)
    cursor = scss_db.cursor()
    # Setting at rest encryption.
    cursor.execute(f'PRAGMA key="{key}"')
    # Checking to see if the scss_user table already exists.
    table_exists = cursor.execute('''
                                  SELECT name
                                  FROM sqlite_master
                                  WHERE name="scss_user"''')
    if table_exists.fetchone() is None:
        # Building table structure.
        cursor.execute('''CREATE TABLE scss_user
                    (
                       username TEXT NOT NULL UNIQUE,
                       password BLOB NOT NULL,
                       userids TEXT NOT NULL,
                       apikey TEXT,
                       totp BLOB,
                       fl_tstamp DATETIME,
                       fl_count INTEGER)
                    ''')
        scss_db.commit()
    else:
        # Table already exists, exiting program.
        log.error(f'{db_name} already exists and has a scss_user table.')
        sys_exit(1)


def register_user(db_name, key, user_data):
    """Takes input, bcrypts it, and writes it to a file.

    Required Input:
    db_name - str(), The location of the DB file.
    user_data - dict(), A dictionary with the following keys:
        username - str(), The unique identifier for the user.
        password - str(), Self-explanatory.
        userids - str(), The unique identifiers that the user will have
        access to in order to retrieve encrypted data.

    Outupt:
    The function writes the username, hashed password, userids, a TOTP
    key and a generated API key to the scss_user database.
    """
    # Logging
    log = getLogger(__name__)
    if exists(db_name):
        try:
            conn = sqlite.connect(db_name)
            cursor = conn.cursor()
            cursor.execute(f'PRAGMA key="{key}"')
            log.debug('Connection to scss_user DB successful')
        except PermissionError:
            log.exception('Unable to open the DB file.  Check permissions.')
            sys_exit(1)
    else:
        log.error('DB file does not exist.  Aborting.')
        sys_exit(1)
    if validate_un(user_data['username']):
        # Converting input as needed.
        if validate_pw(user_data['password']):
            pwd = user_data['password'].encode(encoding='ascii')
            h_pwd = hashpw(b64encode(sha512(pwd).digest()), gensalt())
            apikey = sha256(b64encode(token_bytes(32))).hexdigest()
            totp = b32encode(token_bytes(20)).decode('ascii').strip('=')
        else:
            print('Password does not meet password requirements')
            exit(1)
        # Writing input to DB.
        log.debug('Writing user data into DB.')
        if ',' in user_data['userids']:
            data = {
                'username': user_data['username'],
                'password': h_pwd.decode(encoding='ascii'),
                'userids': user_data['userids'].split(','),
                'apikey': apikey,
                'topt': totp,
                'fl_tstamp': 'None',
                'fl_count': '0'
                }
            cursor.execute('''"INSERT INTO scss_user
                           VALUES
                           (:username,
                            :password,
                            :userids,
                            :apikey,
                            :topt,
                            :fl_tstamp,
                            :fl_count
                           )
                ''', data)
            conn.commit()
        else:
            data = {
                'username': user_data['username'],
                'password': h_pwd.decode(encoding='ascii'),
                'userids': user_data['userids'],
                'apikey': apikey,
                'totp': totp,
                'fl_tstamp': 'None',
                'fl_count': '0'
                }
            cursor.execute('''"INSERT INTO scss_user
                           VALUES
                           (:username,
                            :password,
                            :userids,
                            :apikey,
                            :topt,
                            :fl_tstamp,
                            :fl_count
                           )
                ''', data)
            conn.commit()
        conn.close()
        return {'apikey': apikey, 'totp': totp}
    else:
        print('User name is not in a valid format.')
        log.error('Input validation for user name failed.')
        sys_exit(1)


def update_pw(db_name, key, username, new_pwd):
    """Updates a user's password.

    Required Input:
    db_name - str(), The database file location.
    key - str(), The key used to encrypt/decrypt the DB.
    username - str(), The unique identifier for the user.
    new_pwd - str(), The user's new password.

    Outputs:
    This function updates the user's password hash in the scss_db.

    Raises:
    PermissionError - Self explanatory.
    sqlite.Error - Base error for exceptions in SQLite3."""
    # Logging
    log = getLogger(__name__)
    # Connecting to DB.
    if exists(db_name):
        try:
            conn = sqlite.connect(db_name)
            cursor = conn.cursor()
            cursor.execute(f'PRAGMA key="{key}"')
            log.debug('Connection to scss_user DB successful')
        except PermissionError:
            log.exception('Unable to open the DB file.  Check permissions.')
            sys_exit(1)
        except sqlite.Error:
            log.exception('Unable to connect to DB due to a SQLite error')
            sys_exit(1)
    else:
        log.error('DB file does not exist.')
        sys_exit(1)
    # Querying to see if the user name exists.
    results = cursor.execute('''SELECT *
                             FROM scss_users
                             WHERE username = ?
                             ''', username)
    if results.fetchone() is None:
        # Since there is no record to update log, print then close
        # the connection.
        print('User does not exist for password update.')
        log.error('User does not exist for password update.')
        conn.close()
        sys_exit(1)
    else:
        # Executing a record update for %username.
        pwd = new_pwd.encode(encoding='ascii')
        h_pwd = hashpw(b64encode(sha512(pwd).digest()), gensalt())
        # Writing password to DB.
        cursor.execute('''UPDATE scss_user
                       SET password = ?
                       WHERE username = ?''',
                       (h_pwd.decode(encoding='ascii'), username))
        conn.commit()
        log.info(f'Password update complete for {username}')
        conn.close()


def update_api_key(db_name, key, username):
    """Updates a user's API key.

    Required Input:
    username - The unique identifier for the user.

    Outputs:
    This function updates the user's API key in the scss_user DB.

    Raises:
    PermissionError - Self explanatory.
    SQLite.Error - Base error class for SQLit3.."""
    # Logging
    log = getLogger(__name__)
    # Connecting to DB.
    if exists(db_name):
        try:
            conn = sqlite.connect(db_name)
            cursor = conn.cursor()
            cursor.execute(f'PRAGMA key="{key}"')
            log.debug('Connection to scss_user DB successful')
        except PermissionError:
            log.exception('Unable to open the DB file.  Check permissions.')
            sys_exit(1)
        except sqlite.Error:
            log.exception('Unable to connect to DB due to a SQLite error')
            sys_exit(1)
    else:
        log.error('DB file does not exist.')
        sys_exit(1)
    # Querying to see if the user name exists.
    results = cursor.execute('''SELECT *
                             FROM scss_users
                             WHERE username = ?
                             ''', username)
    if results.fetchone() is None:
        # Since there is no record to update log, print then close
        # the connection.
        print('User does not exist for API key update.')
        log.error('User does not exist for API key update.')
        conn.close()
        sys_exit(1)
    else:
        # Executing an API key record update for %username.
        apikey = sha256(b64encode(token_bytes(32))).hexdigest()
        # Writing new API key to DB.
        cursor.execute('''UPDATE scss_user
                       SET apikey = ?
                       WHERE username = ?''',
                       (apikey, username))
        conn.commit()
        log.info(f'API key update complete for {username}')
        conn.close()
    return apikey


def update_otp_token(db_name, key, username):
    """Updates a user's TOTP token.

    Required Input:
    db_name - str(), The location of the SQLite DB file.
    key - str(), The key used to decrypt/encrypt the DB.
    username - str(), The unique identifier for the user.

    Outputs:
    This function updates the user's TOTP token in the scss_user DB.

    Raises:
    PermissionError - Self explanatory.
    FileNotFoundError - Self explanatory."""
    # Logging
    log = getLogger(__name__)
    # Connecting to DB.
    if exists(db_name):
        try:
            conn = sqlite.connect(db_name)
            cursor = conn.cursor()
            cursor.execute(f'PRAGMA key="{key}"')
            log.debug('Connection to scss_user DB successful')
        except PermissionError:
            log.exception('Unable to open the DB file.  Check permissions.')
            sys_exit(1)
        except sqlite.Error:
            log.exception('Unable to connect to DB due to a SQLite error')
            sys_exit(1)
    else:
        log.error('DB file does not exist.')
        sys_exit(1)
    # Querying to see if the user name exists.
    results = cursor.execute('''SELECT *
                             FROM scss_users
                             WHERE username = ?
                             ''', username)
    if results.fetchone() is None:
        # Since there is no record to update log, print then close
        # the connection.
        print('User does not exist for API key update.')
        log.error('User does not exist for API key update.')
        conn.close()
        sys_exit(1)
    else:
        # Executing an API key record update for %username.
        otp = b32encode(token_bytes(20)).decode('ascii').strip('=')
        # Writing new API key to DB.
        cursor.execute('''UPDATE scss_user
                       SET totp = ?
                       WHERE username = ?''',
                       (otp, username))
        conn.commit()
        log.info(f'OTP token key update complete for {username}')
        conn.close()
    return otp


def check_pw(username, password):
    """Returns true if bcrypted password matches provided input.

    Required Input:
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

    Required Input:
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

    Required Input:
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
    f_headers = ['username', 'password', 'userids', 'apikey', 'totp',
                 'fl_tstamp', 'fl_count']
    writer = DictWriter(pwd_file, fieldnames=f_headers)
    writer.writeheader()
    for entry in user_data:
        writer.writerow(entry)
    pwd_file.close()


def unlock_user(username):
    """Sets failed login count to 0 for username.

    Required Input:
    username - The unique identifier for the user.

    Outputs:
    Returns True if the failed login count has been succesfully set to
    zero."""
    pwd_file = open(u_file, 'r', encoding='ascii')
    user_data = []
    reader = DictReader(pwd_file)
    for row in reader:
        if username == row['username']:
            # Checking to see when the last failed login occurred.
            row['fl_tstamp'] = 'None'
            row['fl_count'] = '0'
        user_data.append(row)
    pwd_file.close()
    # Writing the new data back into the file.
    pwd_file = open(u_file, 'w', newline='', encoding='ascii')
    f_headers = ['username', 'password', 'userids', 'apikey', 'totp',
                 'fl_tstamp', 'fl_count']
    writer = DictWriter(pwd_file, fieldnames=f_headers)
    writer.writeheader()
    for entry in user_data:
        writer.writerow(entry)
    pwd_file.close()
    pwd_file = open(u_file, 'r', encoding='ascii')
    reader = DictReader(pwd_file)
    for row in reader:
        if username == row['username']:
            if int(row['fl_count']) == 0 and row['fl_tstamp'] == 'None':
                return True
            else:
                return False
    pwd_file.close()


def lock_user(username):
    """Sets failed login count to 10 for username.

    Required Input:
    username - The unique identifier for the user.

    Outputs:
    Returns True if the failed login count has been succesfully set to
    ten."""
    pwd_file = open(u_file, 'r', encoding='ascii')
    user_data = []
    reader = DictReader(pwd_file)
    for row in reader:
        if username == row['username']:
            # Checking to see when the last failed login occurred.
            row['fl_tstamp'] = str(time())
            row['fl_count'] = '10'
        user_data.append(row)
    pwd_file.close()
    # Writing the new data back into the file.
    pwd_file = open(u_file, 'w', newline='', encoding='ascii')
    f_headers = ['username', 'password', 'userids', 'apikey', 'totp',
                 'fl_tstamp', 'fl_count']
    writer = DictWriter(pwd_file, fieldnames=f_headers)
    writer.writeheader()
    for entry in user_data:
        writer.writerow(entry)
    pwd_file.close()
    pwd_file = open(u_file, 'r', encoding='ascii')
    reader = DictReader(pwd_file)
    for row in reader:
        if username == row['username']:
            if int(row['fl_count']) == 10 and row['fl_tstamp'] != 'None':
                return True
            else:
                return False
    pwd_file.close()


def map_api_to_user(apikey):
    """Returns the username associated with a given API key.

    Required Input:
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

    Required Input:
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

    Required Input:
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

    Required Input:
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

    Required Input:
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

    Required Input:
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

    Required Input:
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
        _userid = escape(userid)
        gpg_file = open(c_text, 'r', encoding='ascii').read().strip('\n')
        g = GPG(homedir=g_home)
        gpg_data = str(g.decrypt(gpg_file, passphrase=g_pass)).split('\n')
        for line in gpg_data:
            reg_search = search(r'(^' + _userid + ': )(.+)', line)
            if reg_search:
                return reg_search.group(2)
    else:
        return False
