# -*- coding: utf-8 -*-

from flask import Blueprint
from ckanext.oauth2.oauth2 import get_came_from
from ckanext.oauth2 import constants
from ckan.common import session
from ckan.plugins import toolkit
from urllib.parse import urlparse


def _get_previous_page(default_page):
    if 'came_from' not in toolkit.request.params:
        came_from_url = toolkit.request.headers.get('Referer', default_page)
    else:
        came_from_url = toolkit.request.params.get('came_from', default_page)

    came_from_url_parsed = urlparse(came_from_url)

    # Avoid redirecting users to external hosts
    if came_from_url_parsed.netloc != '' and came_from_url_parsed.netloc != toolkit.request.host:
        came_from_url = default_page

    # When a user is being logged and REFERER == HOME or LOGOUT_PAGE
    # he/she must be redirected to the dashboard
    pages = ['/', '/user/logged_out_redirect']
    if came_from_url_parsed.path in pages:
        came_from_url = default_page

    return came_from_url


def _challenge(oauth2helper, challenge_url):
    def inner(id=None):
        came_from_url = _get_previous_page(constants.INITIAL_PAGE)
        return oauth2helper.challenge(challenge_url, came_from_url)
    return inner


def callback(oauth2helper):
    def inner():
        try:
            token = oauth2helper.get_token()
            user_name = oauth2helper.identify(token)
            headers = oauth2helper.remember(user_name)
            oauth2helper.update_token(user_name, token)
            return oauth2helper.redirect_from_callback(headers)
        except Exception as e:
            session.save()

            # If the callback is called with an error, we must show the message
            error_description = toolkit.request.params.get('error_description')
            if not error_description:
                if hasattr(e, 'message') and e.message:
                    error_description = e.message
                elif hasattr(e, 'description') and e.description:
                    error_description = e.description
                elif hasattr(e, 'error') and e.error:
                    error_description = e.error
                else:
                    error_description = type(e).__name__

            redirect_url = get_came_from(toolkit.request.params.get('state'))
            redirect_url = '/' if redirect_url == constants.INITIAL_PAGE else redirect_url
            toolkit.h.flash_error(error_description)
            return toolkit.h.redirect_to(redirect_url)
    return inner



def get_blueprints(plugin):
    oauth2_blueprint = Blueprint('oauth2', __name__)

    oauth2_blueprint.add_url_rule('/{}'.format(constants.REDIRECT_URL), endpoint="callback", view_func=callback(plugin.oauth2helper))
    oauth2_blueprint.add_url_rule('/user/login', endpoint="login", view_func=_challenge(plugin.oauth2helper, plugin.authorization_endpoint))

    if plugin.register_url:
        oauth2_blueprint.add_url_rule('/user/register', endpoint="register", view_func=_challenge(plugin.oauth2helper, plugin.register_url))
    if plugin.reset_url:
        oauth2_blueprint.add_url_rule('/user/reset', endpoint="reset", view_func=_challenge(plugin.oauth2helper, plugin.reset_url))
    if plugin.edit_url:
        oauth2_blueprint.add_url_rule('/user/edit/<id>', endpoint="edit", view_func=_challenge(plugin.oauth2helper, plugin.edit_url))


    return [oauth2_blueprint]
