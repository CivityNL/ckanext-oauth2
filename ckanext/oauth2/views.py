# -*- coding: utf-8 -*-

from flask import Blueprint
from ckanext.oauth2.oauth2 import get_came_from
from ckanext.oauth2 import constants
from ckan.common import session
from ckan.plugins import toolkit
from urlparse import urlparse


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


def login(oauth2helper):
    def inner():
        # Log in attempts are fired when the user is not logged in and they click
        # on the login button

        # Get the page where the user was when the login attempt was fired
        # When the user is not logged in, he/she should be redirected to the dashboard when
        # the system cannot get the previous page
        came_from_url = _get_previous_page(constants.INITIAL_PAGE)
        return oauth2helper.challenge(came_from_url)
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



def get_blueprints(oauth2helper):
    oauth2_blueprint = Blueprint('oauth2', __name__)

    oauth2_blueprint.add_url_rule('/user/login', endpoint="login", view_func=login(oauth2helper))
    oauth2_blueprint.add_url_rule('/oauth2/callback', endpoint="callback", view_func=callback(oauth2helper))

    return [oauth2_blueprint]
