# Copyright 2023 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

from datetime import datetime
import os
import traceback
import string
import secrets

from django.contrib.auth.backends import BaseBackend
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser

from pangea.services.authn.authn import AuthN
from pangea.config import PangeaConfig

UserModel = get_user_model()

def generate_state_param(request: HttpRequest) -> str:
    alphabet = string.ascii_letters + string.digits
    state = ''.join(secrets.choice(alphabet) for i in range(12))
    request.session["PANGEA_LOGIN_STATE"] = state
    return state


class PangeaAuthMiddleware():
    class InvalidSessionException(Exception):
        pass

    def __init__(self, get_response):
        self.authn = PangeaAuthentication()
        self.get_response = get_response

    def __call__(self, request: HttpRequest):
        active_token = None
        try:
            active_token = request.session.get("PANGEA_ACTIVE_TOKEN")
            if active_token:
                expires = active_token["expire"]
                try:
                    expires = datetime.fromisoformat(expires)
                except ValueError:
                    # support older python that doesn't understand the trailing Z
                    expires = datetime.fromisoformat(expires.rstrip("Z"))
                if expires < datetime.utcnow():
                    refresh_token = request.session["PANGEA_REFRESH_TOKEN"]["token"]
                    response = self.authn.client.refresh(refresh_token=refresh_token)
                    if not response.status == 'Success':
                        raise self.InvalidSessionException
                    active_token = response["active_token"]
                    response.session["PANGEA_ACTIVE_TOKEN"] = active_token
            else:
                raise self.InvalidSessionException
        except self.InvalidSessionException as e:
            request.user = AnonymousUser()
        else:
            request.user = self.authn.get_user(username=active_token["email"])

        return self.get_response(request)

class PangeaAuthentication(BaseBackend):
    def __init__(self):
        token = os.getenv("PANGEA_AUTHN_TOKEN")
        domain = os.getenv("PANGEA_DOMAIN")
        self.config = PangeaConfig(domain=domain)
        self.authn = AuthN(token, config=self.config, logger_name="pangea")
        super().__init__()

    def authenticate(self, request: HttpRequest):
        code = request.GET.get('code')
        state = request.GET.get('state')
        expected_state = request.session.get("PANGEA_LOGIN_STATE")
        user = None
        if not code or not expected_state or state != expected_state:
            return None
        resp = self.authn.client.userinfo(code=code)
        if resp and resp.status == "Success":
            try:
                refresh = resp.raw_result['refresh_token']
                active = resp.raw_result['active_token']
                user, created = UserModel.objects.get_or_create(username=active["email"])
                if created:
                    user.email = active["email"]
                    user.first_name = active["profile"]["first_name"]
                    user.last_name = active["profile"]["last_name"]
                    user.last_login = active["profile"]["Last-Login-Time"]
                    user.is_active = True
                    user.save()
                else:
                    user.last_login = active["profile"]["Last-Login-Time"]
                    user.save()
                request.session["PANGEA_REFRESH_TOKEN"] = refresh
                request.session["PANGEA_ACTIVE_TOKEN"] = active
                if "PANGEA_LOGIN_STATE" in request.session:
                    del request.session["PANGEA_LOGIN_STATE"]
            except Exception as e:
                print(traceback.format_exc())
        if not user:
            request.session["PANGEA_REFRESH_TOKEN"] = None
            request.session["PANGEA_ACTIVE_TOKEN"] = None
            request.session["PANGEA_USER"] = None
        return user

    def logout(self, request: HttpRequest):
        active = request.session.get("PANGEA_ACTIVE_TOKEN")
        token = active.get("token")
        if token:
            self.authn.client.session.logout(token)
        if "PANGEA_ACTIVE_TOKEN" in request.session:
            del request.session["PANGEA_ACTIVE_TOKEN"]
        if "PANGEA_REFRESH_TOKEN" in request.session:
            del request.session["PANGEA_REFRESH_TOKEN"]
        if "PANGEA_USER" in request.session:
            del request.session["PANGEA_USER"] = None

    def user_can_authenticate(self, user):
        return getattr(user, "is_active", True)

    def get_user(self, user_id=None, username=None):
        if not user_id and not username:
            raise ValueError("user_id or username is required")
        try:
            if user_id:
                user = UserModel.objects.get(pk=user_id)
            else:
                user = UserModel.objects.get(username=username)
        except UserModel.DoesNotExist:
            return None
        return user if self.user_can_authenticate(user) else None
