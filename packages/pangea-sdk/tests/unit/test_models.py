from __future__ import annotations

from unittest import TestCase

from pangea.services.authn.models import FlowUpdateDataProfile, Profile


class TestModels(TestCase):
    def test_authn_profile(self) -> None:
        profile: dict[str, str] = {"first_name": "Name", "last_name": "Last"}
        profile["foo"] = "bar"
        Profile(profile)
        FlowUpdateDataProfile(profile=profile)
