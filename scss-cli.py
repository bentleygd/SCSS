#!/usr/bin/python3
from argparse import ArgumentParser

from scssbin.scss import register_user


aparser = ArgumentParser(prog='SCSS user administration')
aparser.add_argument('action', help='The action to perform.', type=str)
args = aparser.parse_args()

if args.action == 'register':
    username = input('What is the username?> ')
    password = input('What is the password?> ')
    userids = input('What userids are authorized for this user?> ')
    api_key = register_user(username, password, userids)
    print(args.username, 'API Key:', api_key)
