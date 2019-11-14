#!/usr/bin/python3
from scssbin import scss
from requests import post


class TestSCSS:
    def test_auth(self):
        test = scss.check_pw('test-user', 'test-password-1234')
        assert test is True

    def test_auth_failure(self):
        test = scss.check_pw('test-user', 'bad_password')
        assert test is False

    def test_api_retrieval(self):
        auth = scss.check_pw('test-user', 'test-password-1234')
        test = scss.get_api_key('test_user', auth)
        assert test != 1

    def test_api_auth(self):
        auth = scss.check_pw('test-user', 'test-password-1234')
        api_key = scss.get_api_key('test-user', auth)
        test = scss.check_api_key('test-user', api_key)
        assert test is True

    def test_pwd_update(self):
        scss.update_pw('test-user', 'test-password-12345')
        test = scss.check_pw('test-user', 'test-password-12345')
        assert test is True


class TestWSGI:
    def test_web_get_api(self):
        headers = {
            'User-Agent': 'scss-client',
            'username': 'test-user',
            'password': 'test-password-12345'
        }
        response = post('http://127.0.0.1:5000/getAPI', headers=headers)
        assert response.status_code == 200

    def test_web_get_fail(self):
        headers = {
            'User-Agent': 'scss-client',
            'username': 'test-user',
            'password': 'bad_password'
        }
        response = post('http://127.0.0.1:5000/getAPI', headers=headers)
        assert response.status_code == 401

    def test_api_header_fail(self):
        headers = {'username': 'test-user', 'password': 'bad_password'}
        response = post('http://127.0.0.1:5000/getAPI', headers=headers)
        assert response.status_code == 400
