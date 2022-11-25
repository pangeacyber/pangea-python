# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

import os
import unittest

import pangea.exceptions as pexc
from pangea import PangeaConfig
from pangea.response import PangeaResponse, ResponseStatus
from pangea.services.authn.authn import AuthN


class TestAuthN(unittest.TestCase):
    def setUp(self):
        self.token = os.getenv("PANGEA_INTEGRATION_AUTHN_TOKEN")
        domain = os.getenv("PANGEA_INTEGRATION_DOMAIN")
        self.config = PangeaConfig(domain=domain)
        self.authn = AuthN(self.token, config=self.config)
