#!/usr/bin/python3
from argparse import ArgumentParser
from configparser import ConfigParser
from subprocess import run, CalledProcessError
from os.path import exists

from scssbin.scss import register_user

# Parsing configuration.
config = ConfigParser()
config.read('scss.ini')
c_text = config['scss-gpg']['data']

# Argument parsing.
help_msg = ('The action to perform.  Possible are actions are: ' +
            'register|start|stop')
aparser = ArgumentParser(prog='SCSS Commande Line Utility')
aparser.add_argument('action', help=help_msg, type=str)
args = aparser.parse_args()

# Doing stuff.
if args.action == 'register':
    username = input('What is the username?> ')
    password = input('What is the password?> ')
    userids = input('What userids are authorized for this user?> ')
    api_key = register_user(username, password, userids)
    print(username, 'API Key:', api_key)

if args.action == 'start':
    g_pass = input('Start-up key> ')
    g_key = open(config['c_text']['key'], 'w', encoding='ascii')
    g_key.write(g_pass.strip('\n'))
    g_key.close()
    try:
        set_own = run(['/bin/chown', 'root:apache', g_key], check=True)
        set_perm = run(['/bin/chmod', '640', g_key], check=True)
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
