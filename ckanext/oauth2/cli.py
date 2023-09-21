# -*- coding: utf-8 -*-

from ckanext.oauth2.model import oauth2_user_token_table
import click


@click.group()
def oauth2():
    """
    keycloak commands
    """
    pass


@oauth2.command()
def initdb():
    """
        keycloak initdb
    """
    oauth2_user_token_table.create()


@oauth2.command()
def cleandb():
    """
        keycloak cleandb
    """
    oauth2_user_token_table.delete()


@oauth2.command()
def dropdb():
    """
        keycloak dropdb
    """
    oauth2_user_token_table.drop()


def get_commands():
    return [oauth2]
