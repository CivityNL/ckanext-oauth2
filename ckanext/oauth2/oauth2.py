# -*- coding: utf-8 -*-

# Copyright (c) 2014 CoNWeT Lab., Universidad Politécnica de Madrid
# Copyright (c) 2018 Future Internet Consulting and Development Solutions S.L.

# This file is part of OAuth2 CKAN Extension.

# OAuth2 CKAN Extension is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# OAuth2 CKAN Extension is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with OAuth2 CKAN Extension.  If not, see <http://www.gnu.org/licenses/>.


from __future__ import unicode_literals

import base64
import ckan.model as model
import db
import json
import logging
from six.moves.urllib.parse import urljoin
import os

from base64 import b64encode, b64decode
from ckan.plugins import toolkit
from oauthlib.oauth2 import InsecureTransportError
import requests
from requests_oauthlib import OAuth2Session
import six

import jwt

import constants
from ckan.model.user import User
from ckanext.oauth2.model import Oauth2UserToken


log = logging.getLogger(__name__)


def generate_state(url):
    return b64encode(bytes(json.dumps({constants.CAME_FROM_FIELD: url}).encode("utf-8")))


def get_came_from(state):
    return json.loads(b64decode(state)).get(constants.CAME_FROM_FIELD, '/')


def get_config(key, default=''):
    return toolkit.config.get(key, default).strip()


REQUIRED_CONF = ("authorization_endpoint", "token_endpoint", "client_id", "client_secret", "profile_api_url", "profile_api_user_field", "profile_api_mail_field")
TRUES = ("true", "1", "on")


class OAuth2Helper(object):

    def __init__(self):

        self.verify_https = os.environ.get('OAUTHLIB_INSECURE_TRANSPORT', '') == ""
        if self.verify_https and os.environ.get("REQUESTS_CA_BUNDLE", "").strip() != "":
            self.verify_https = os.environ["REQUESTS_CA_BUNDLE"].strip()

        self.jwt_enable = get_config(constants.JWT_ENABLE).lower() in TRUES

        self.legacy_idm = get_config(constants.LEGACY_IDM).strip().lower() in TRUES
        self.authorization_endpoint = get_config(constants.AUTHORIZATION_ENDPOINT)
        self.token_endpoint = get_config(constants.TOKEN_ENDPOINT)
        self.profile_api_url = get_config(constants.PROFILE_API_URL)
        self.client_id = get_config(constants.CLIENT_ID)
        self.client_secret = get_config(constants.CLIENT_SECRET)
        self.scope = get_config(constants.SCOPE)
        self.rememberer_name = get_config(constants.REMEMBERER_NAME, 'auth_tkt')
        self.profile_api_user_field = get_config(constants.PROFILE_FIELD_USER)
        self.profile_api_fullname_field = get_config(constants.PROFILE_FIELD_FULLNAME)
        self.profile_api_mail_field = get_config(constants.PROFILE_FIELD_EMAIL)
        self.profile_api_groupmembership_field = get_config(constants.PROFILE_FIELD_GROUPMEMBERSHIP)
        self.sysadmin_group_name = get_config(constants.SYSADMIN_GROUP_NAME)

        self.redirect_uri = urljoin(
            urljoin(
                toolkit.config.get('ckan.site_url', 'http://localhost:5000'),
                toolkit.config.get('ckan.root_path')
            ), constants.REDIRECT_URL
        )

        missing = [key for key in REQUIRED_CONF if getattr(self, key, "") == ""]
        if missing:
            raise ValueError("Missing required oauth2 conf: %s" % ", ".join(missing))
        elif self.scope == "":
            self.scope = None

    def challenge(self, came_from_url):
        # This function is called by the log in function when the user is not logged in
        state = generate_state(came_from_url)
        oauth = OAuth2Session(self.client_id, redirect_uri=self.redirect_uri, scope=self.scope, state=state)
        auth_url, _ = oauth.authorization_url(self.authorization_endpoint)
        log.debug('Challenge: Redirecting challenge to page {0}'.format(auth_url))
        # CKAN 2.6 only supports bytes
        return toolkit.redirect_to(auth_url.encode('utf-8'))

    def get_token(self):
        oauth = OAuth2Session(self.client_id, redirect_uri=self.redirect_uri, scope=self.scope)

        # Just because of FIWARE Authentication
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded',
        }

        if self.legacy_idm:
            # This is only required for Keyrock v6 and v5
            headers['Authorization'] = 'Basic %s' % base64.urlsafe_b64encode(
                '%s:%s' % (self.client_id, self.client_secret)
            )

        try:
            token = oauth.fetch_token(self.token_endpoint,
                                      headers=headers,
                                      client_secret=self.client_secret,
                                      authorization_response=toolkit.request.url,
                                      verify=self.verify_https)
        except requests.exceptions.SSLError as e:
            # TODO search a better way to detect invalid certificates
            if "verify failed" in six.text_type(e):
                raise InsecureTransportError()
            else:
                raise

        return token

    def identify(self, token):

        if self.jwt_enable:

            access_token = bytes(token['access_token'])
            user_data = jwt.decode(access_token, verify=False)
            user = self.user_json(user_data)
        else:

            try:
                if self.legacy_idm:
                    profile_response = requests.get(self.profile_api_url + '?access_token=%s' % token['access_token'], verify=self.verify_https)
                else:
                    oauth = OAuth2Session(self.client_id, token=token)
                    profile_response = oauth.get(self.profile_api_url, verify=self.verify_https)

            except requests.exceptions.SSLError as e:
                # TODO search a better way to detect invalid certificates
                if "verify failed" in six.text_type(e):
                    raise InsecureTransportError()
                else:
                    raise

            # Token can be invalid
            if not profile_response.ok:
                error = profile_response.json()
                if error.get('error', '') == 'invalid_token':
                    raise ValueError(error.get('error_description'))
                else:
                    profile_response.raise_for_status()
            else:
                user_data = profile_response.json()
                user = self.user_json(user_data)

        # Save the user in the database
        model.Session.add(user)
        model.Session.commit()
        model.Session.remove()

        return user.name

    def user_json(self, user_data):
        email = user_data[self.profile_api_mail_field]
        user_name = user_data[self.profile_api_user_field]

        # In CKAN can exists more than one user associated with the same email
        # Some providers, like Google and FIWARE only allows one account per email
        user = User.get(user_name)

        # If the user does not exist, we have to create it...
        if user is None:
            user = User(email=email)

        # When a user successfully logs in, we set the user state to active.
        # This will convert a user from deleted into active when needed.
        user.state = 'active'

        # Now we update his/her user_name with the one provided by the OAuth2 service
        # In the future, users will be obtained based on this field
        user.name = user_name

        # Update fullname
        if self.profile_api_fullname_field != "" and self.profile_api_fullname_field in user_data:
            user.fullname = user_data[self.profile_api_fullname_field]

        # Update sysadmin status
        if self.profile_api_groupmembership_field != "" and self.profile_api_groupmembership_field in user_data:
            user.sysadmin = self.sysadmin_group_name in user_data[self.profile_api_groupmembership_field]

        return user

    def _get_rememberer(self, environ):
        plugins = environ.get('repoze.who.plugins', {})
        return plugins.get(self.rememberer_name)

    def remember(self, user_name):
        '''
        Remember the authenticated identity.

        This method simply delegates to another IIdentifier plugin if configured.
        '''
        log.debug('Repoze OAuth remember')
        environ = toolkit.request.environ
        rememberer = self._get_rememberer(environ)
        identity = {'repoze.who.userid': user_name}
        headers = rememberer.remember(environ, identity)
        return headers


    def redirect_from_callback(self, headers):
        '''Redirect to the callback URL after a successful authentication.'''
        state = toolkit.request.params.get('state')
        came_from = get_came_from(state)
        response = toolkit.h.redirect_to(came_from)
        for header, value in headers:
            response.headers.add(header, value)
        return response


    def get_stored_token(self, user_name):
        oauth2_user_token = Oauth2UserToken.by_user_name(user_name=user_name)
        if oauth2_user_token:
            return {
                'access_token': oauth2_user_token.access_token,
                'expires_at': oauth2_user_token.expires_at,
                'expires_in': oauth2_user_token.expires_in,
                'id_token': oauth2_user_token.id_token,
                'not-before-policy': oauth2_user_token.not_before_policy,
                'refresh_expires_in': oauth2_user_token.refresh_expires_in,
                'refresh_token': oauth2_user_token.refresh_token,
                'session_state': oauth2_user_token.session_state,
                'scope': oauth2_user_token.scope.split() if oauth2_user_token.scope else None,
                'token_type': oauth2_user_token.token_type,
            }

    def update_token(self, user_name, token):

        oauth2_user_token = Oauth2UserToken.by_user_name(user_name=user_name)
        # Create the user if it does not exist
        if not oauth2_user_token:
            oauth2_user_token = Oauth2UserToken()
            oauth2_user_token.user_name = user_name

        # Save the new token
        oauth2_user_token.access_token = token['access_token']
        oauth2_user_token.expires_at = token['expires_at']
        oauth2_user_token.id_token = token['id_token']
        oauth2_user_token.not_before_policy = token['not-before-policy']
        oauth2_user_token.refresh_expires_in = token['refresh_expires_in']
        oauth2_user_token.refresh_token = token['refresh_token']
        oauth2_user_token.session_state = token['session_state']
        oauth2_user_token.scope = " ".join(token['scope']) if isinstance(token['scope'], list) else token['scope']
        oauth2_user_token.token_type = token['token_type']

        if 'expires_in' in token:
            oauth2_user_token.expires_in = token['expires_in']
        else:
            access_token = jwt.decode(oauth2_user_token.access_token, verify=False)
            oauth2_user_token.expires_in = access_token['exp'] - access_token['iat']

        model.Session.add(oauth2_user_token)
        model.Session.commit()

    def refresh_token(self, user_name):
        token = self.get_stored_token(user_name)
        if token:
            client = OAuth2Session(self.client_id, token=token, scope=self.scope)
            try:
                token = client.refresh_token(self.token_endpoint, client_secret=self.client_secret, client_id=self.client_id, verify=self.verify_https)
            except requests.exceptions.SSLError as e:
                # TODO search a better way to detect invalid certificates
                if "verify failed" in six.text_type(e):
                    raise InsecureTransportError()
                else:
                    raise
            self.update_token(user_name, token)
            log.info('Token for user %s has been updated properly' % user_name)
            return token
        else:
            log.warning('User %s has no refresh token' % user_name)
