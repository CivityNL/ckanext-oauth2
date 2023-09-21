from sqlalchemy import types, Column, Table
import ckan.model as model

oauth2_user_token_table = Table('oauth2_user_token', model.meta.metadata,
                                Column('user_name', types.UnicodeText, primary_key=True),
                                Column('access_token', types.UnicodeText),
                                Column('expires_at', types.Integer),
                                Column('expires_in', types.Integer),
                                Column('id_token', types.UnicodeText),
                                Column('not_before_policy', types.Integer),
                                Column('refresh_expires_in', types.Integer),
                                Column('refresh_token', types.UnicodeText),
                                Column('session_state', types.UnicodeText),
                                Column('scope', types.UnicodeText),
                                Column('token_type', types.UnicodeText),
                                )


class Oauth2UserToken(model.DomainObject):

    @classmethod
    def by_user_name(cls, user_name):
        return model.Session.query(cls).filter_by(user_name=user_name).first()


model.meta.mapper(Oauth2UserToken, oauth2_user_token_table)
