#!/usr/bin/python3
from argparse import ArgumentParser
from configparser import ConfigParser
from subprocess import run, CalledProcessError
from os.path import exists

from scssbin import scss

# Parsing configuration.
config = ConfigParser()
config.read('scss.ini')
c_text = config['scss-gpg']['data']

# Argument parsing.
help_msg = ('The action to perform.  Possible are actions are: ' +
            'register|update-api|update-pw|update-totp|unlock|lock' +
            '|start|stop')
aparser = ArgumentParser(prog='SCSS Commande Line Utility')
aparser.add_argument('action', help=help_msg, type=str)
args = aparser.parse_args()

# Doing stuff.
if args.action.lower() == 'register':
    username = input('What is the username?> ')
    password = input('What is the password?> ')
    userids = input('What userids are authorized for this user?> ')
    user_data = scss.register_user(username, password, userids)
    api_key = user_data['apikey']
    totp = user_data['totp']
    print(username, 'API Key:', api_key, '\nTOTP:', totp)

if args.action.lower() == 'update-api':
    username = input('What is the username?> ')
    api_key = scss.update_api_key(username)
    print('The new api key for %s is %s' % (username, api_key))

if args.action.lower() == 'update-totp':
    username = input('What is the username?> ')
    totp = scss.update_otp_token(username)
    print('The new TOTP token for %s is %s' % (username, totp))

if args.action.lower() == 'update-pw':
    username = input('What is the username?> ')
    password = input('What is the new password?> ')
    scss.update_pw(username, password)
    update_check = scss.check_pw(username, password)
    if update_check:
        print('Password succesfully changed for %s' % username)
    else:
        print('Password not changed for %s' % username)

if args.action.lower() == 'unlock':
    username = input('What is the username?> ')
    unlock = scss.unlock_user(username)
    if unlock:
        print('%s has been succesfully unlocked.' % username)
    else:
        print('Failed to unlock account for %s' % username)

if args.action.lower() == 'lock':
    username = input('What is the username?> ')
    lock = scss.lock_user(username)
    if lock:
        print('%s has been succesfully locked.' % username)
    else:
        print('Failed to lock account for %s' % username)

if args.action.lower() == 'start':
    g_pass = input('Start-up key> ')
    g_key = open(config['scss-gpg']['key'], 'w', encoding='ascii')
    g_key.write(g_pass.strip('\n'))
    g_key.close()
    try:
        set_own = run(
            ['/usr/bin/chown', 'root:apache', config['scss-gpg']['key']],
            check=True)
        set_perm = run(
            ['/usr/bin/chmod', '640', config['scss-gpg']['key']],
            check=True)
    except CalledProcessError:
        print('Non-zero return code when trying to set ownership or' +
              'permissions.  Script must be executed by root.  Exiting.')
        exit(1)
    try:
        apache_start = run(
            ['/bin/systemctl', 'start', 'httpd.service'], check=True
            )
    except CalledProcessError:
        print('Non-zero return code when trying to start Apache.  Exiting.')
        exit(1)

if args.action == 'stop':
    g_key = config['c_text']['key']
    if exists(g_key):
        try:
            file_remove = run(['/bin/shred', '--remove', g_key], check=True)
        except CalledProcessError:
            print('Unable to remove key file.  Check permissions.')
            exit(1)
        if file_remove.returncode == 0:
            apache_stop = run(['/bin/systemctl', 'stop', 'httpd.service'])
            exit(0)
    else:
        apache_stop = run(['/bin/systemctl', 'stop', 'httpd.service'])
        exit(0)
