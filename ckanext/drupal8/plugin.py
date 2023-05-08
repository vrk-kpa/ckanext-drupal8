import logging
import urllib
import uuid
import hashlib
import base64

import sqlalchemy as sa

import ckan.plugins as p
import ckan.logic as logic
import ckan.lib.helpers as h
from ckan.common import g
from ckanext.drupal8 import views
from ckan import model

if p.toolkit.check_ckan_version(min_version='2.10.0'):
    from flask_login import login_user, logout_user
else:
    from ckan.common import session


log = logging.getLogger('ckanext.saml2')


def _no_permissions(context, msg):
    user = context['user']
    return {'success': False, 'msg': msg.format(user=user)}


@logic.auth_sysadmins_check
def user_create(context, data_dict):
    msg = p.toolkit._('Users cannot be created.')
    return _no_permissions(context, msg)


@logic.auth_sysadmins_check
def user_update(context, data_dict):
    msg = p.toolkit._('Users cannot be edited.')
    return _no_permissions(context, msg)


@logic.auth_sysadmins_check
def user_reset(context, data_dict):
    msg = p.toolkit._('Users cannot reset passwords.')
    return _no_permissions(context, msg)


@logic.auth_sysadmins_check
def request_reset(context, data_dict):
    msg = p.toolkit._('Users cannot reset passwords.')
    return _no_permissions(context, msg)


class Drupal8Plugin(p.SingletonPlugin):

    p.implements(p.IAuthenticator, inherit=True)
    p.implements(p.IAuthFunctions, inherit=True)
    p.implements(p.IConfigurer)
    p.implements(p.IConfigurable)
    p.implements(p.ITemplateHelpers)
    p.implements(p.IBlueprint)

    drupal_session_names = None

    def get_helpers(self):
        return {'ckanext_drupal8_domain': self.get_domain}

    def get_domain(self):
        return self.domain

    def update_config(self, config):
        p.toolkit.add_template_directory(config, 'templates')

    def configure(self, config):
        domain = config.get('ckanext.drupal8.domain')
        self.sysadmin_role = config.get('ckanext.drupal8.sysadmin_role')
        self.connection = config.get('ckanext.drupal8.connection')
        self.allow_edit = config.get(
            'ckanext.drupal8.allow_edit', 'false') == 'true'

        if not (domain and self.sysadmin_role and self.connection):
            raise Exception('Drupal8 extension has not been configured')

        if len(domain.split(':')) > 2:
            raise Exception('Unexpected domain format. We expect at most one colon (example.com or example.com:port)')

        self.domains = [item.strip() for item in domain.split(",")]
        self.domain = self.domains[0]

    def make_password(self):
        # create a hard to guess password
        out = ''
        for n in range(8):
            out += str(uuid.uuid4())
        return out

    def create_drupal_session_names(self):
        self.drupal_session_names = []
        domains = self.domains + [p.toolkit.request.environ['HTTP_HOST']]
        for domain in domains:
            domain_hash = hashlib.sha256(domain.encode('utf-8')).hexdigest()[:32]
            self.drupal_session_names.append('SESS%s' % domain_hash)
            self.drupal_session_names.append('SSESS%s' % domain_hash)  # https

    def identify(self):
        ''' This does work around saml2 authorization.
        c.user contains the saml2 id of the logged in user we need to
        convert this to represent the ckan user. '''

        # If no drupal sesssion name create one
        if self.drupal_session_names in (None, []):
            self.create_drupal_session_names()
        # Can we find the user?
        cookies = p.toolkit.request.cookies

        user = None
        for drupal_session_name in self.drupal_session_names:
            drupal_sid = cookies.get(drupal_session_name)
            if drupal_sid:
                # Drupal session ids now need to be unquoted
                drupal_sid = urllib.parse.unquote(drupal_sid)
                sid_hash = hashlib.sha256(drupal_sid.encode('utf-8')).digest()
                encoded_sid_hash = base64.urlsafe_b64encode(sid_hash).replace(b"=", b'')
                encoded_sid_hash_str = encoded_sid_hash.decode('utf-8')

                engine = sa.create_engine(self.connection)
                rows = engine.execute('SELECT u.name, u.mail, t.entity_id as uid FROM users_field_data u '
                                      'JOIN sessions s on s.uid=u.uid LEFT OUTER JOIN '
                                      '(SELECT r.roles_target_id as role_name, r.entity_id FROM user__roles r '
                                      '     WHERE r.roles_target_id=%s '
                                      ') AS t ON t.entity_id = u.uid '
                                      'WHERE s.sid=%s AND u.name != \'\'',
                                      [self.sysadmin_role, encoded_sid_hash_str])

                for row in rows:
                    user = self.user(row)
                    break

        g.user = user
        g.userobj = model.User.by_name(user)

        if p.toolkit.check_ckan_version(min_version='2.10.0'):
            if g.userobj:
                login_user(g.userobj)
            else:
                logout_user()
        elif g.user:
            session.save()
        
    def _email_hash(self, email):
        return hashlib.md5(email.strip().lower().encode('utf8')).hexdigest()

    def user(self, user_data):
        try:
            user = p.toolkit.get_action('user_show')(
                {'keep_email': True, 'ignore_auth': True}, {'id': user_data.name})
        except p.toolkit.ObjectNotFound:
            user = None

        if user:
            # update the user in ckan if not matching drupal data
            email_hash = user.get("email_hash", None)

            if not email_hash:
                email_hash = self._email_hash(user.get("email"))

            if (self._email_hash(user_data.mail) != email_hash
                    or bool(user_data.uid) != user['sysadmin']):
                user['email'] = user_data.mail
                user['sysadmin'] = bool(user_data.uid)
                user['id'] = user_data.name
                user['fullname'] = user_data.name
                user = p.toolkit.get_action('user_update')(
                    {'user': user['id'], 'ignore_auth': True}, user)
        else:
            user = {'email': user_data.mail,
                    'name': user_data.name,
                    'password': self.make_password(),
                    'sysadmin': bool(user_data.uid), }
            user = p.toolkit.get_action('user_create')(
                {'user': None, 'ignore_auth': True}, user)
        return user['name']

    def abort(self, status_code, detail, headers, comment):
        # HTTP Status 401 causes a login redirect.  We need to prevent this unless we are actually trying to login.
        # The original ckanext-drupal8 aborts redirects, we actually want to be redirected to login page in case a user has not
        # been logged in yet.
        # self.identify()
        if (status_code == 401 and p.toolkit.c.user is not None):
            h.redirect_to('drupal8_unauthorized')
        return (status_code, detail, headers, comment)

    def get_auth_functions(self):
        # we need to prevent some actions being authorized.
        auth_functions = {
            'user_create': user_create,
            'user_reset': user_reset,
            'request_reset': request_reset,
        }
        if not self.allow_edit:
            auth_functions['user_update'] = user_update
        return auth_functions

    # IBlueprint

    def get_blueprint(self):
        return views.get_blueprints()
