#!/usr/bin/python3
from argparse import ArgumentParser

from scssbin import register_user


aparser = ArgumentParser(prog='SCSS user registration')
aparser.add_argument('username', help='The user to register.', type=str)
aparser.add_argument('password', help='The password for the user.')
aparser.add_argument('userids', help='User IDs that the user can use for GPG')
args = aparser.parse_args()

api_key = register_user(args.username, args.password, args.userids)
print(args.username, 'API Key:', api_key)
