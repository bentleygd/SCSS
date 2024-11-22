# SCSS
Somewhat secure credential storage service.


[![Known Vulnerabilities](https://snyk.io/test/github/bentleygd/CSIC/badge.svg?targetFile=requirements.txt)](https://snyk.io/test/github/bentleygd/CSIC?targetFile=requirements.txt) ![CodeQL](https://github.com/bentleygd/SCSS/workflows/CodeQL/badge.svg)


## Motivation
The purpose of this project is to provide a means of storing credentials in an encrypted fashion, and to be able to retrieve those credentials via an API call.  This is to reduce the presence of stored secrets in plain text files and in code.

## Features
The SCSS API encrypts credentials using GPG.  Passwords used to authenticate and generate API keys are hashed using bcrypt.  Credentials are st

## Install
For now, you have to clone the repo.

`$ git clone https://github.com/bentleygd/SCSS.git`

## Usage
You have to make API calls to retrieve any stored credentials.  He is an example using the requests module:

```python
from requests import get
from configparser import ConfigParser


config = ConfigParser()
config.read('some_file')
api_key = config['api']['key']
otp = TOTP(sconfig['api']['otp']).now()
userid = some_userid
url = path_to_api
user_agent = 'scss-client'  # This is important.
# Building HTTP headers.
headers = {
    'User-Agent': user_agent,
    'api-key': api_key,
    'totp': otp,
    'userid': userid
}
# Connecting to SCSS.
scss_response = post(url, headers=headers)
if scss_response.status_code == 200:
    data = scss_response.json().get('gpg_pass')  # These are the retrieved credentials
    log.debug('Credentials successfully retrieved from SCSS')
else:
    log.error('Unable to retrieve credentials from SCSS.  The HTTP '
                'error code is %s', scss_response.status_code)
    exit(1)
```


# Code Documentation

## `register_user(username, password, userids)`
Registers a new user, hashes their password, and writes user data to a file.

### Required Input:
- `username` (str): The unique identifier for the user.
- `password` (str): The user's password.
- `userids` (str): A comma-separated string of unique identifiers that the user will have access to for retrieving encrypted data.

### Output:
- Writes the username, hashed password, userids, a TOTP key, and a generated API key to the user file.
- Returns a dictionary containing the API key and TOTP token.

---

## `update_pw(username, new_pwd)`
Updates an existing user's password in the user file.

### Required Input:
- `username` (str): The unique identifier for the user.
- `new_pwd` (str): The new password for the user.

### Output:
- Updates the user's password in the file.
- Raises:
  - `PermissionError`: If there is an issue with file access.
  - `FileNotFoundError`: If the user file is not found.

---

## `update_api_key(username)`
Generates and updates a new API key for the specified user.

### Required Input:
- `username` (str): The unique identifier for the user.

### Output:
- Updates the user's API key in the user file and returns the new API key.
- Raises:
  - `PermissionError`: If there is an issue with file access.
  - `FileNotFoundError`: If the user file is not found.

---

## `update_otp_token(username)`
Generates and updates a new TOTP token for the specified user.

### Required Input:
- `username` (str): The unique identifier for the user.

### Output:
- Updates the user's TOTP token in the user file and returns the new TOTP token.
- Raises:
  - `PermissionError`: If there is an issue with file access.
  - `FileNotFoundError`: If the user file is not found.

---

## `check_pw(username, password)`
Checks if the provided password matches the stored hashed password for the specified user.

### Required Input:
- `username` (str): The unique identifier for the user.
- `password` (str): The password to be checked.

### Output:
- Returns `True` if the password matches the stored hash and the account is not locked.
- Returns `False` otherwise.

---

## `fail_login(username)`
Records a failed login attempt for a user.

### Required Input:
- `username` (str): The unique identifier for the user.

### Output:
- Increments the failed login counter and records the timestamp of the failed attempt.

---

## `fail_api_login(apikey)`
Records a failed login attempt using the API key.

### Required Input:
- `apikey` (str): The API key of the user.

### Output:
- Increments the failed login counter and records the timestamp of the failed attempt.

---

## `unlock_user(username)`
Resets the failed login count to zero for a specified user, unlocking their account.

### Required Input:
- `username` (str): The unique identifier for the user.

### Output:
- Returns `True` if the failed login count has been successfully reset to zero.

---

## `lock_user(username)`
Locks a user's account by setting their failed login count to 10.

### Required Input:
- `username` (str): The unique identifier for the user.

### Output:
- Returns `True` if the failed login count has been successfully set to 10.

---

## `map_api_to_user(apikey)`
Returns the username associated with a given API key.

### Required Input:
- `apikey` (str): The unique API key for the user.

### Output:
- Returns the username associated with the provided API key.

---

## `good_login(username)`
Resets the failed login count to zero upon a successful login.

### Required Input:
- `username` (str): The unique identifier for the user.

### Output:
- Resets the failed login count to zero if the user has previously failed to log in.

---

## `get_api_key(username, loginstatus)`
Returns the API key for the specified user if login was successful.

### Required Input:
- `username` (str): The unique identifier for the user.
- `loginstatus` (bool): The login status (`True` for success, `False` for failure).

### Output:
- Returns the user's API key if login is successful; `False` otherwise.

---

## `check_api_key(key)`
Checks if a given API key is valid.

### Required Input:
- `key` (str): The API key to be checked.

### Output:
- Returns `True` if the API key is valid, `False` otherwise.

---

## `check_totp(totp, key)`
Validates the TOTP (Time-based One-Time Password) for a given API key.

### Required Input:
- `totp` (str): The TOTP provided by the user.
- `key` (str): The API key associated with the user.

### Output:
- Returns `True` if the TOTP is valid, `False` otherwise.

---

## `check_userid(apistatus, key, userid)`
Checks if the user has access to the specified `userid` based on their API key.

### Required Input:
- `apistatus` (bool): The result of `check_api_key`.
- `key` (str): The API key.
- `userid` (str): The unique identifier for the data being accessed.

### Output:
- Returns `True` if the user has access to the `userid`, `False` otherwise.

---

## `get_gpg_pwd(apistatus, userid_status, mfa, userid, g_home, g_pass)`
Returns the GPG password if all input conditions are met.

### Required Input:
- `apistatus` (bool): The result of `check_api_key`.
- `userid_status` (bool): The result of `check_userid`.
- `mfa` (bool): The result of `check_totp`.
- `userid` (str): The unique identifier for the user.
- `g_home` (str): The GPG home directory.
- `g_pass` (str): The passphrase for the GPG key.

### Output:
- Returns the GPG password if all conditions are met; `False` otherwise.

