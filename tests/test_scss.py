#!/usr/bin/python3
from scssbin import scss
from scssbin.validate import validate_api_key
from requests import post, get
from pyotp import TOTP


class TestSCSS:
    def test_auth_failure(self):
        test = scss.check_pw('test-user', 'bad_password')
        assert test is False

    def test_auth(self):
        test = scss.check_pw('test-user', 'test-password-1234')
        assert test is True

    def test_api_retrieval(self):
        auth = scss.check_pw('test-user', 'test-password-1234')
        test = scss.get_api_key('test-user', auth)
        assert test is not False

    def test_api_key_format(self):
        auth = scss.check_pw('test-user', 'test-password-1234')
        apikey = scss.get_api_key('test-user', auth)
        test = validate_api_key(apikey)
        assert test is True

    def test_api_auth(self):
        auth = scss.check_pw('test-user', 'test-password-1234')
        api_key = scss.get_api_key('test-user', auth)
        test = scss.check_api_key(api_key)
        assert test is True

    def test_api_auth_fail(self):
        api_key = 'bad_data' * 8
        test = scss.check_api_key(api_key)
        assert test is False

    def test_mfa(self):
        auth = scss.check_pw('test-user', 'test-password-1234')
        api_key = scss.get_api_key('test-user', auth)
        otp = TOTP('2UVQE7LDNU5XZWANIDTJA43W6I').now()
        test = scss.check_totp(otp, api_key)
        assert test is True

    def test_userid(self):
        auth = scss.check_pw('test-user', 'test-password-1234')
        api_key = scss.get_api_key('test-user', auth)
        api_status = scss.check_api_key(api_key)
        test = scss.check_userid(api_status, api_key, 'nobody@domain.com')
        assert test is True

    def test_userid_fail(self):
        auth = scss.check_pw('test-user', 'test-password-1234')
        api_key = scss.get_api_key('test-user', auth)
        api_status = scss.check_api_key(api_key)
        test = scss.check_userid(api_status, api_key, 'bob@domain.com')
        assert test is False

    def test_pwd_update(self):
        scss.update_pw('test-user', 'test-password-12345')
        test = scss.check_pw('test-user', 'test-password-12345')
        assert test is True

    def test_api_update(self):
        api_key = scss.update_api_key('test-user')
        test = scss.check_api_key(api_key)
        assert test is True

    def test_account_lock(self):
        test = scss.lock_user('test-user')
        assert test is True

    def test_account_unlock(self):
        test = scss.unlock_user('test-user')
        assert test is True


class TestWSGI:
    def test_web_get_api_fail(self):
        headers = {
            'User-Agent': 'scss-client',
            'username': 'test-user',
            'password': 'bad_password'
        }
        response = post(
            'http://127.0.0.1:5000/getAPI',
            headers=headers,
            timeout=5
            )
        assert response.status_code == 401

    def test_web_get_api(self):
        headers = {
            'User-Agent': 'scss-client',
            'username': 'test-user',
            'password': 'test-password-12345'
        }
        response = post(
            'http://127.0.0.1:5000/getAPI',
            headers=headers,
            timeout=5
            )
        assert response.status_code == 200

    # def test_get_gpg(self):
    #    api_headers = {
    #        'User-Agent': 'scss-client',
    #        'username': 'test-user',
    #        'password': 'test-password-12345'
    #    }
    #    api_url = 'http://127.0.0.1:5000/getAPI'
    #    api_response = post(api_url, headers=api_headers)
    #    api_key = api_response.json().get('apikey')
    #    otp = TOTP('2UVQE7LDNU5XZWANIDTJA43W6I').now()
    #    gpg_headers = {
    #        'User-Agent': 'scss-client',
    #        'api-key': api_key,
    #        'totp': otp,
    #        'userid': 'nobody@domain.com'
    #    }
    #    gpg_url = 'http://127.0.0.1:5000/getGPG'
    #    gpg_response = post(gpg_url, headers=gpg_headers)
    #    gpg_data = gpg_response.json().get('gpg_pass')
    #    assert len(gpg_data) == 64

#    def test_get_gpg_fail_auth(self):
#        api_key = 'baddata1' * 8
#        gpg_headers = {
#            'User-Agent': 'scss-client',
#            'api-key': api_key,
#            'userid': 'nobody@domain.com',
#            'totp': '123456'
#        }
#        gpg_url = 'http://127.0.0.1:5000/getGPG'
#        response = post(gpg_url, headers=gpg_headers)
#        assert response.status_code == 403
#
#    def test_get_gpg_unauth(self):
#        api_headers = {
#            'User-Agent': 'scss-client',
#            'username': 'test-user',
#            'password': 'test-password-12345'
#        }
#        api_url = 'http://127.0.0.1:5000/getAPI'
#        api_response = post(api_url, headers=api_headers)
#        api_key = api_response.json().get('apikey')
#        otp = TOTP('2UVQE7LDNU5XZWANIDTJA43W6I').now()
#        gpg_headers = {
#            'User-Agent': 'scss-client',
#            'api-key': api_key,
#            'totp': otp,
#            'userid': 'bob@domain.com'
#        }
#        gpg_url = 'http://127.0.0.1:5000/getGPG'
#        gpg_response = post(gpg_url, headers=gpg_headers)
#        assert gpg_response.status_code == 403

    def test_wsgi_session_cookies(self):
        headers = {
            'User-Agent': 'scss-client',
            'username': 'test-user',
            'password': 'some_other_password'
        }
        url = 'http://127.0.0.1:5000/getAPI'
        response = post(url, headers=headers, timeout=5)
        assert 'session' in response.cookies

    def test_wsgi_method_getapi(self):
        headers = {
            'User-Agent': 'scss-client',
            'username': 'test-user',
            'password': 'some_other_password'
        }
        url = 'http://127.0.0.1:5000/getAPI'
        response = get(url, headers=headers, timeout=5)
        assert response.status_code == 405

#    def test_wsgi_method_getgpg(self):
#        headers = {
#            'User-Agent': 'scss-client',
#            'username': 'test-user',
#            'password': 'some_other_password'
#        }
#        url = 'http://127.0.0.1:5000/getGPG'
#        response = get(url, headers=headers)
#        assert response.status_code == 405
