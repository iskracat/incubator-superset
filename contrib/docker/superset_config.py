# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
import os
import jwt
import requests

from flask_appbuilder.security.manager import AUTH_REMOTE_USER
from superset.security import SupersetSecurityManager
from flask import redirect, g, flash, request
from flask_appbuilder._compat import as_unicode
from flask_appbuilder.security.views import AuthRemoteUserView
from flask_appbuilder.security.views import expose
from flask_login import login_user


def get_env_variable(var_name, default=None):
    """Get the environment variable or raise exception."""
    try:
        return os.environ[var_name]
    except KeyError:
        if default is not None:
            return default
        else:
            error_msg = 'The environment variable {} was missing, abort...'\
                        .format(var_name)
            raise EnvironmentError(error_msg)


POSTGRES_USER = get_env_variable('POSTGRES_USER')
POSTGRES_PASSWORD = get_env_variable('POSTGRES_PASSWORD')
POSTGRES_HOST = get_env_variable('POSTGRES_HOST')
POSTGRES_PORT = get_env_variable('POSTGRES_PORT')
POSTGRES_DB = get_env_variable('POSTGRES_DB')

# The SQLAlchemy connection string.
SQLALCHEMY_DATABASE_URI = 'postgresql://%s:%s@%s:%s/%s' % (POSTGRES_USER,
                                                           POSTGRES_PASSWORD,
                                                           POSTGRES_HOST,
                                                           POSTGRES_PORT,
                                                           POSTGRES_DB)
REDIS_HOST = get_env_variable('REDIS_HOST')
REDIS_PORT = get_env_variable('REDIS_PORT')


class CeleryConfig(object):
    BROKER_URL = 'redis://%s:%s/0' % (REDIS_HOST, REDIS_PORT)
    CELERY_IMPORTS = ('superset.sql_lab', )
    CELERY_RESULT_BACKEND = 'redis://%s:%s/1' % (REDIS_HOST, REDIS_PORT)
    CELERY_ANNOTATIONS = {'tasks.add': {'rate_limit': '10/s'}}
    CELERY_TASK_PROTOCOL = 1


CELERY_CONFIG = CeleryConfig


class RemoteUserMiddleware(object):
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        return self.app(environ, start_response)


ADDITIONAL_MIDDLEWARE = [RemoteUserMiddleware]


class OpenAMValidator:
    def __init__(self, token):
        self.token = token

    def is_valid(self):
        url = "https://217.182.160.199:8443/openam/identity/isTokenValid"  # noqa

        resp = requests.post(url, verify=False, data=f"tokenid={self.token}", headers={
            "Host": "openam.beedata.beedataanalytics.com",
            "Content-Type": "application/x-www-form-urlencoded",
        })
        if resp.text.rstrip("\n") != "boolean=true":
            return None
        return True


class MiCustomRemoteUserView(AuthRemoteUserView):
    @expose('/login/')
    def login(self):
        jwt_options = {'verify_signature': False}
        token = request.args.get('token', '')
        try:
            # Get the token from the url
            token_decoded = jwt.decode(token, options=jwt_options)
            # Decode it and get the OpenAM token
            open_am_token = token_decoded["access_token"]
            roles = token_decoded["roles"]
            username = token_decoded["id"]
            open_am_validator = OpenAMValidator(open_am_token)
            is_valid = open_am_validator.is_valid()
            user_mapping = {
                "username": username,
                "first_name": username,
                "last_name": username,
                "email": f"{username}@beedata.cat"
            }
        except (jwt.exceptions.ExpiredSignatureError, jwt.exceptions.DecodeError):
            return redirect("https://dashboard.bee.iskra.cat/login")
        sm = self.appbuilder.sm
        role = sm.find_role(sm.auth_role_public)
        # If user has role beedata.SuperUser assign admin role
        if 'beedata.SuperUser' in roles:
            role = sm.find_role(sm.auth_role_admin)
        user_mapping["role"] = role
        if g.user is not None and g.user.is_authenticated:
            return redirect(self.appbuilder.get_url_for_index)
        session = sm.get_session
        user = session.query(sm.user_model).filter_by(username=username).first()
        if user:
            if not user.is_active:
                return (
                    "Your account is not activated, "
                    "ask an admin to check the 'Is Active?' box in your "
                    "user profile")
        if username and is_valid:
            user = self.appbuilder.sm.auth_user_remote_user(username)
            if user is None:
                # Create User if it does not exists and log in
                user = sm.add_user(**user_mapping)
                msg = ("Welcome to Superset, {}".format(username))
                flash(as_unicode(msg), 'info')
                user = sm.auth_user_remote_user(username)
                login_user(user)
                return redirect(self.appbuilder.get_url_for_index)
            else:
                # Log in if user exists
                login_user(user)
                return redirect(self.appbuilder.get_url_for_index)
        return redirect("https://dashboard.bee.iskra.cat/login")


class MiCustomSecurityManager(SupersetSecurityManager):
    authremoteuserview = MiCustomRemoteUserView


AUTH_TYPE = AUTH_REMOTE_USER
CUSTOM_SECURITY_MANAGER = MiCustomSecurityManager
