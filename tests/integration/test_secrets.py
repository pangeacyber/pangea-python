import os
import random
import unittest

from pangea import PangeaConfig
from pangea.services import Secrets


class TestRedact(unittest.TestCase):
    def setUp(self):
        token = os.getenv("PANGEA_TEST_INTEGRATION_TOKEN")
        config_id = os.getenv("SECRETS_INTEGRATION_CONFIG_ID")
        config = PangeaConfig(base_domain="dev.pangea.cloud", config_id=config_id)
        self.secrets = Secrets(token, config=config)

    def test_add_new_id(self):
        secret_id = "test_" + str(random.randint(10, 10000000))
        secret_value = secret_id + "_value"

        response = self.secrets.add(secret_id, secret_value)
        expected_id = secret_id

        self.assertEqual(response.code, 200)
        self.assertEqual(response.result.get("secret_id"), expected_id)

    def test_add_same_id(self):
        secret_id = "test_" + str(random.randint(10, 10000000))
        secret_value = secret_id + "_value"

        response = self.secrets.add(secret_id, secret_value)
        self.assertEqual(response.code, 200)

        response = self.secrets.add(secret_id, secret_value)
        self.assertEqual(response.code, 500)

    def test_get_non_existent(self):
        secret_id = "test_" + str(random.randint(10, 10000000))

        response = self.secrets.get(secret_id)
        self.assertEqual(response.code, 404)

    def test_get_without_version(self):
        secret_id = "test_" + str(random.randint(10, 10000000))
        secret_value = secret_id + "_value"

        self.secrets.add(secret_id, secret_value)
        response = self.secrets.get(secret_id)
        expected_id = secret_id
        expected_value = secret_value

        self.assertEqual(response.code, 200)
        self.assertEqual(response.result.get("secret_id"), expected_id)
        self.assertEqual(response.result.get("secret_value"), expected_value)

    def test_get_with_version(self):
        secret_id = "test_" + str(random.randint(10, 10000000))
        secret_value = secret_id + "_value"

        response = self.secrets.add(secret_id, secret_value)
        self.assertEqual(response.code, 200)
        secret_version = response.result.get("secret_version")

        response = self.secrets.get(secret_id, secret_version)
        expected_id = secret_id
        expected_value = secret_value
        expected_version = secret_version

        self.assertEqual(response.code, 200)
        self.assertEqual(response.result.get("secret_id"), expected_id)
        self.assertEqual(response.result.get("secret_value"), expected_value)
        self.assertEqual(response.result.get("secret_version"), expected_version)

    def test_update_existent_id(self):
        secret_id = "test_" + str(random.randint(10, 10000000))
        secret_value = secret_id + "_value"

        response = self.secrets.add(secret_id, secret_value)
        self.assertEqual(response.code, 200)
        secret_version = response.result.get("secret_version")

        response = self.secrets.update(secret_id, secret_value)
        expected_id = secret_id      

        self.assertEqual(response.code, 200)
        self.assertEqual(response.result.get("secret_id"), expected_id)
        self.assertNotEqual(response.result.get("secret_version"), secret_version)        

        old_version = response.result.get("secret_version")
        secret_value = secret_value + "_new"
        response = self.secrets.update(secret_id, secret_value)
        self.assertEqual(response.code, 200)
        self.assertEqual(response.result.get("secret_id"), expected_id)
        self.assertNotEqual(response.result.get("secret_version"), old_version)

    def test_update_non_existent_id(self):
        secret_id = "test_" + str(random.randint(10, 10000000))
        secret_value = secret_id + "_value"

        response = self.secrets.update(secret_id, secret_value)    

        self.assertEqual(response.code, 500)
