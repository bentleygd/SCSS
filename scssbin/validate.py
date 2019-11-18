#!/usr/bin/python3
from re import match


def validate_un(username):
    """Returns true if string input matches user name pattern."""
    if match(r'[a-zA-Z0-9_-]{1,32}', username):
        return True
    else:
        return False


def validate_pw(password):
    """Returns true if password meets requirements."""
    if (match(r'[\x21-\x7E]{14,32}', password) and
            not match(r'(.)\1\1', password)):
        return True
    else:
        return False


def validate_userid(userid):
    """"Returns true if userid passes validation."""
    if match(r'[a-zA-Z0-9_-]{1,32}\@[a-zA-Z0-9\.-]{1,96}', userid):
        return True
    else:
        return False


def validate_api_key(api_key):
    """Returns true if api key passes validation."""
    if match(r'[a-f0-9]{64}', api_key):
        return True
    else:
        return False
