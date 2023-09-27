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

import logging
from ckanext.oauth2 import oauth2, constants
import requests
from functools import partial
from ckan import plugins
from ckan.plugins import toolkit
from ckanext.oauth2 import auth, views, cli


log = logging.getLogger(__name__)



class OAuth2Plugin(plugins.SingletonPlugin):

    plugins.implements(plugins.IAuthenticator, inherit=True)
    plugins.implements(plugins.IAuthFunctions, inherit=True)
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.IBlueprint)
    plugins.implements(plugins.IClick)

    register_url = None
    reset_url = None
    edit_url = None
    authorization_header = None
    logout_url = None
    authorization_endpoint = None
    oauth2helper = None

    # IClick
    def get_commands(self):
        return cli.get_commands()

    # IBlueprint
    def get_blueprint(self):
        return views.get_blueprints(self)

    # IAuthenticator
    def identify(self):
        log.debug('identify')

        def _refresh_and_save_token(user_name):
            new_token = self.oauth2helper.refresh_token(user_name)
            if new_token:
                toolkit.g.oauth_user_token = new_token

        environ = toolkit.request.environ
        apikey = toolkit.request.headers.get(self.authorization_header, '')
        user_name = None

        if self.authorization_header == "authorization":
            if apikey.startswith('Bearer '):
                apikey = apikey[7:].strip()
            else:
                apikey = ''

        # This API Key is not the one of CKAN, it's the one provided by the OAuth2 Service
        if apikey:
            try:
                token = {'access_token': apikey}
                user_name = self.oauth2helper.identify(token)
            except Exception:
                pass

        # If the authentication via API fails, we can still log in the user using session.
        if user_name is None and 'repoze.who.identity' in environ:
            user_name = environ['repoze.who.identity']['repoze.who.userid']
            log.debug('User {} logged using session'.format(user_name))

        # If we have been able to log in the user (via API or Session)
        if user_name:
            toolkit.g.user = user_name
            toolkit.g.oauth_user_token = self.oauth2helper.get_stored_token(user_name)
            toolkit.g.oauth_user_token_refresh = partial(_refresh_and_save_token, user_name)
        else:
            toolkit.g.user = None
            log.warning('The user is not currently logged...')

    # IAuthenticator
    # noinspection PyMethodMayBeStatic
    def logout(self):
        log.debug('logout')
        oauth_user_token = getattr(toolkit.g, "oauth_user_token", None)
        if oauth_user_token:
            log.debug('logout with oauth_user_token = {}'.format(oauth_user_token))
            del toolkit.request.environ['repoze.who.identity']
            # check the validity of the token
            params = {"id_token_hint": oauth_user_token['id_token']}
            log.debug('logout_url = [{}], params = [{}]'.format(self.logout_url, params))
            requests.get(self.logout_url, params=params)
            self.oauth2helper.delete_stored_token(toolkit.g.user)


    # IAuthFunctions
    def get_auth_functions(self):
        # we need to prevent some actions being authorized.
        return {
            'user_create': auth.user_create,
            'user_update': auth.user_update,
            'user_reset': auth.user_reset,
            'request_reset': auth.request_reset
        }

    # IConfigurer
    def update_config(self, config):
        # Update our configuration
        self.register_url = config.get(constants.REGISTER_ENDPOINT, None)
        self.reset_url = config.get(constants.RESET_ENDPOINT, None)
        self.edit_url = config.get(constants.EDIT_ENDPOINT, None)
        self.authorization_header = config.get(constants.AUTHORIZATION_HEADER, 'Authorization').lower()
        self.logout_url = config.get(constants.LOGOUT_ENDPOINT, None)
        self.authorization_endpoint = config.get(constants.AUTHORIZATION_ENDPOINT)

        self.oauth2helper = oauth2.OAuth2Helper(self.authorization_endpoint)

        # Add this plugin's templates dir to CKAN's extra_template_paths, so
        # that CKAN will use this plugin's custom templates.
        plugins.toolkit.add_template_directory(config, 'templates')
