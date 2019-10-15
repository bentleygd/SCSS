#!/usr/bin/python3
from re import match


def validate_un(username):
    """Returns true if string input matches user name pattern."""
    if match(r'[a-zA-Z0-9_-]{1,32}', username):
        return True
    else:
        return False
