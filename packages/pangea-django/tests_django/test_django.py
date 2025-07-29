from __future__ import annotations

from collections.abc import Generator
from datetime import datetime, timedelta, timezone
from secrets import token_hex
from typing import Generic
from unittest.mock import MagicMock, patch

import pytest
from django.contrib.auth.models import User
from django.contrib.sessions.middleware import SessionMiddleware
from django.test import TestCase
from django.test.client import RequestFactory
from pangea.response import PangeaResponseResult, ResponseHeader, ResponseStatus
from pangea.services.authn.authn import AuthN
from pangea.services.authn.models import (
    ClientSessionLogoutResult,
    ClientSessionRefreshResult,
    ClientUserinfoResult,
    LoginToken,
)
from typing_extensions import TypeVar

from pangea_django.pangea_django_auth import PangeaAuthentication, PangeaAuthMiddleware, generate_state_param

T = TypeVar("T", bound=PangeaResponseResult)


class MockPangeaResponse(ResponseHeader, Generic[T]):
    """Lightweight mock of a PangeaResponse."""

    result: T | None = None

    def __init__(self, result: T, status: ResponseStatus = ResponseStatus.SUCCESS) -> None:
        super().__init__(status=status.value, request_id="", request_time="", response_time="", summary="")
        self.result = result


login_token = LoginToken(
    created_at=datetime.now(tz=timezone.utc).isoformat(),
    email="placeholder",
    expire=datetime.now(tz=timezone.utc).isoformat(),
    id="",
    identity="",
    life=0,
    profile={"first_name": "Alice", "last_name": "Bob"},
    token="",
    type="user",
)


@pytest.fixture()
def session_refresh() -> Generator[MagicMock, None, None]:
    """Mock session refresh."""

    with patch.object(AuthN.Client.Session, "refresh") as mocked_refresh:
        mocked_refresh.return_value = MockPangeaResponse(
            result=ClientSessionRefreshResult(
                active_token=login_token.model_copy(update={"token": "new_active_token"}),
                refresh_token=login_token.model_copy(update={"token": "new_refresh_token"}),
            )
        )
        yield mocked_refresh


@pytest.fixture()
def session_logout() -> Generator[MagicMock, None, None]:
    """Mock session logout."""

    with patch.object(AuthN.Client.Session, "logout") as mocked_logout:
        mocked_logout.return_value = MockPangeaResponse(result=ClientSessionLogoutResult())
        yield mocked_logout


@pytest.fixture()
def client_userinfo() -> Generator[MagicMock, None, None]:
    """Mock client userinfo."""

    with patch.object(AuthN.Client, "userinfo") as mocked_userinfo:
        mocked_userinfo.return_value = MockPangeaResponse(
            result=ClientUserinfoResult(
                active_token=login_token.model_copy(update={"token": "new_active_token"}),
                refresh_token=login_token.model_copy(update={"token": "new_refresh_token"}),
            )
        )
        yield mocked_userinfo


class TestDjango(TestCase):
    def setUp(self) -> None:
        # Environment variables.
        self.monkeypatch = pytest.MonkeyPatch()
        self.monkeypatch.setenv("PANGEA_AUTHN_TOKEN", "placeholder")
        self.monkeypatch.setenv("PANGEA_DOMAIN", "placeholder")

        # Minimal request.
        request_factory = RequestFactory()
        self.request = request_factory.get("/")
        middleware = SessionMiddleware(lambda _: None)  # type: ignore[arg-type]
        middleware.process_request(self.request)
        self.request.session.save()

    def tearDown(self) -> None:
        self.monkeypatch.undo()

    def test_generate_state_param(self) -> None:
        state = generate_state_param(self.request)
        assert len(state) >= 12
        assert self.request.session["PANGEA_LOGIN_STATE"] == state

    def test_unauthenticated(self) -> None:
        middleware = PangeaAuthMiddleware(lambda _: None)
        middleware(self.request)
        assert self.request.user.is_anonymous

    @pytest.mark.django_db()
    @pytest.mark.usefixtures("session_refresh")
    def test_refresh_expired_token(self) -> None:
        User.objects.create_user(username="placeholder")

        self.request.session["PANGEA_ACTIVE_TOKEN"] = {
            "expire": (datetime.now(tz=timezone.utc) - timedelta(hours=1)).isoformat(),
        }
        self.request.session["PANGEA_REFRESH_TOKEN"] = {"token": "placeholder"}

        middleware = PangeaAuthMiddleware(lambda _: None)
        middleware(self.request)
        assert not self.request.user.is_anonymous
        assert self.request.session["PANGEA_ACTIVE_TOKEN"]["token"] == "new_active_token"

    @pytest.mark.usefixtures("session_logout")
    def test_logout(self) -> None:
        self.request.session["PANGEA_ACTIVE_TOKEN"] = {
            "expire": datetime.now(tz=timezone.utc).isoformat(),
            "token": "placeholder",
        }
        self.request.session["PANGEA_REFRESH_TOKEN"] = {"token": "placeholder"}

        PangeaAuthentication().logout(self.request)
        assert "PANGEA_ACTIVE_TOKEN" not in self.request.session
        assert "PANGEA_REFRESH_TOKEN" not in self.request.session
        assert "PANGEA_USER" not in self.request.session

    @pytest.mark.usefixtures("client_userinfo")
    def test_authenticate(self) -> None:
        state = token_hex(16)
        self.request.session["PANGEA_LOGIN_STATE"] = state
        self.request.GET = {"code": "some_code", "state": state}  # type: ignore[assignment]

        PangeaAuthentication().authenticate(self.request)
        assert self.request.session["PANGEA_ACTIVE_TOKEN"]["token"] == "new_active_token"
        assert self.request.session["PANGEA_REFRESH_TOKEN"]["token"] == "new_refresh_token"
