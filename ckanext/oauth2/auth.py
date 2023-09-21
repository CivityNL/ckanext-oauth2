import ckan.plugins.toolkit as toolkit


def _no_permissions(context, msg):
    if 'ignore_auth' in context and context['ignore_auth']:
        return {'success': True}
    user = context['user']
    return {'success': False, 'msg': msg.format(user=user)}


@toolkit.auth_sysadmins_check
def user_create(context, data_dict):
    msg = toolkit._('Users cannot be created.')
    return _no_permissions(context, msg)


@toolkit.auth_sysadmins_check
def user_update(context, data_dict):
    msg = toolkit._('Users cannot be edited.')
    return _no_permissions(context, msg)


@toolkit.auth_sysadmins_check
def user_reset(context, data_dict):
    msg = toolkit._('Users cannot reset passwords.')
    return _no_permissions(context, msg)


@toolkit.auth_sysadmins_check
def request_reset(context, data_dict):
    msg = toolkit._('Users cannot reset passwords.')
    return _no_permissions(context, msg)
