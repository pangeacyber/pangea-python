import datetime
import inspect
import logging
import os
import random
import unittest
from typing import Dict, List, Optional

import pangea.exceptions as pexc
from pangea import PangeaConfig
from pangea.response import PangeaResponse
from pangea.services.vault.models.asymmetric import CreateKeyPairResult, KeyPairAlgorithm, KeyPairPurpose
from pangea.services.vault.models.common import CreateCommonResult, Medatada, Tags
from pangea.services.vault.models.symmetric import CreateKeyResult, KeyAlgorithm
from pangea.services.vault.vault import Vault
from pangea.utils import setup_logger, str2str_b64

TIME = datetime.datetime.now().strftime("%m%d_%H%M%S")
LOG_LEVEL = logging.DEBUG
LOG_PATH = f"./logs/{TIME}/"
LOG_FORMATTER = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
THIS_FUNCTION_NAME = lambda: inspect.stack()[1][3]
ENABLE_ASSERT_RESPONSES = True


def combine_lists(dict_list: List[Dict], field_values: List, field_name: str):
    dest: List[Dict] = []
    for d in dict_list:
        for v in field_values:
            d_copy = d.copy()
            d_copy[field_name] = v
            dest.append(d_copy)
    return dest


class TestVault(unittest.TestCase):
    def setUp(self):
        self.token = os.getenv("PANGEA_INTEGRATION_VAULT_TOKEN")
        # domain = os.getenv("PANGEA_INTEGRATION_DOMAIN")
        # self.config = PangeaConfig(domain=domain)

        domain = os.getenv("PANGEA_BRANCH_DOMAIN")
        self.config = PangeaConfig(domain=domain, environment="local")
        print("Domain: ", domain)
        print("Token: ", self.token)

        self.vault = Vault(self.token, config=self.config)
        self.random_id = str(random.randint(10, 1000000000))

        self.managed_values: List[Optional[bool]] = [True, False]  # FIXME: add None to check default cases
        self.store_values: List[Optional[bool]] = [True, False]  # FIXME: add None to check default cases
        self.name_values: List[Optional[str]] = [None, f"name_{self.random_id}"]
        self.folder_values: List[Optional[str]] = [None, f"test/folder_{self.random_id}/"]
        self.metadata_values: List[Optional[Medatada]] = [None, {"info1": 1, "info2": 2, "random_id": self.random_id}]
        self.tags_values: List[Optional[Tags]] = [None, ["tag1", "tag2", f"tag_{self.random_id}"]]
        self.auto_rotate_values: List[Optional[bool]] = [True, False]  # FIXME: add None to check default cases
        self.rotation_policy_values: List[Optional[str]] = [
            None,
            "1D",
        ]  # FIXME: update to timedelta once implemented in backend
        self.retain_previous_version_values: List[Optional[bool]] = [
            True,
            False,
        ]  # FIXME: add None to check default cases
        self.expiration_values: List[Optional[datetime.datetime]] = [None, datetime.timedelta(days=2)]
        self.common_param_comb = [{}]
        # FIXME: Uncomment to test all possible combination cases
        # self.common_param_comb = combine_lists(self.common_param_comb, self.name_values, "name")
        # self.common_param_comb = combine_lists(self.common_param_comb, self.folder_values, "folder")
        # self.common_param_comb = combine_lists(self.common_param_comb, self.metadata_values, "metadata")
        # self.common_param_comb = combine_lists(self.common_param_comb, self.tags_values, "tags")
        self.common_param_comb = combine_lists(self.common_param_comb, self.auto_rotate_values, "auto_rotate")
        self.common_param_comb = combine_lists(self.common_param_comb, self.rotation_policy_values, "rotation_policy")
        # self.common_param_comb = combine_lists(self.common_param_comb, self.expiration_values, "expiration")
        self.common_param_comb = combine_lists(
            self.common_param_comb, self.retain_previous_version_values, "retain_previous_version"
        )

        # this params will be used just for keys
        self.key_param_comb = combine_lists(self.common_param_comb, self.managed_values, "managed")
        self.key_param_comb = combine_lists(self.key_param_comb, self.store_values, "store")

    def create_secret_check_response(self, response: PangeaResponse[CreateCommonResult], params: Dict[str, any]):
        if ENABLE_ASSERT_RESPONSES is not True:
            return

        with self.subTest(msg=f"Create secret check {params}"):
            self.assertEqual(1, response.result.version)
            self.assertIsNotNone(response.result.id)

    def create_key_check_common_response(
        self, response: PangeaResponse[CreateKeyResult | CreateKeyPairResult], params: Dict[str, any]
    ):
        if ENABLE_ASSERT_RESPONSES is not True:
            return
        with self.subTest(msg=f"Create key check common {params}"):
            self.assertEqual(1, response.result.version)
            if params["store"] is False:
                self.assertIsNone(response.result.id)
            else:
                self.assertIsNotNone(response.result.id)

    def create_symmetric_check_response(self, response: PangeaResponse[CreateKeyResult], params: Dict[str, any]):
        if ENABLE_ASSERT_RESPONSES is not True:
            return
        self.create_key_check_common_response(response, params)
        with self.subTest(msg=f"Create symetric check common {params}"):
            if params["store"] is False:
                self.assertIsNotNone(response.result.key)
            else:
                if params["managed"] is False:
                    self.assertIsNotNone(response.result.key)
                else:
                    self.assertIsNone(response.result.key)

    def create_asymmetric_check_response(self, response: PangeaResponse[CreateKeyPairResult], params: Dict[str, any]):
        if ENABLE_ASSERT_RESPONSES is not True:
            return
        self.create_key_check_common_response(response, params)
        with self.subTest(msg=f"Create asymmetric check common {params}"):
            self.assertIsNotNone(response.result.public_key)
            if params["store"] is False:
                self.assertIsNotNone(response.result.private_key)
            else:
                if params["managed"] is False:
                    self.assertIsNotNone(response.result.private_key)
                else:
                    self.assertIsNone(response.result.private_key)

    def encrypting_cycle(self, id):
        msg = "thisisamessagetoencrypt"
        data_b64 = str2str_b64(msg)

        # Encrypt 1
        try:
            encrypt1_resp = self.vault.encrypt(id, data_b64)
        except pexc.PangeaAPIException as e:
            print(f"Response: {e.response}")
            if e.errors:
                print("Error details: ")
                for ef in e.errors:
                    print(f"\t {ef.detail}")
            self.assertTrue(False)

        # self.assertEqual(id, encrypt1_resp.result.id)
        # self.assertEqual(1, encrypt1_resp.result.version)
        cipher_v1 = encrypt1_resp.result.cipher_text
        self.assertIsNotNone(cipher_v1)

        # Rotate
        rotate_resp = self.vault.rotate_key(id)
        self.assertEqual(2, rotate_resp.result.version)
        self.assertEqual(id, rotate_resp.result.id)

        # Encrypt 2
        encrypt2_resp = self.vault.encrypt(id, data_b64)
        # self.assertEqual(id, encrypt2_resp.result.id)
        # self.assertEqual(2, encrypt2_resp.result.version)
        cipher_v2 = encrypt2_resp.result.cipher_text
        self.assertIsNotNone(cipher_v2)

        # Decrypt 1
        try:
            decrypt1_resp = self.vault.decrypt(id, cipher_v1, 1)
        except pexc.PangeaAPIException as e:
            print(f"Response: {e.response}")
            if e.errors:
                print("Error details: ")
                for ef in e.errors:
                    print(f"\t {ef.detail}")
        self.assertEqual(data_b64, decrypt1_resp.result.plain_text)

        # Decrypt 2
        decrypt2_resp = self.vault.decrypt(id, cipher_v2, 2)
        self.assertTrue(data_b64, decrypt2_resp.result.plain_text)

        # Decrypt default version
        decrypt_default_resp = self.vault.decrypt(id, cipher_v2)
        self.assertEqual(data_b64, decrypt_default_resp.result.plain_text)

        # Decrypt wrong version
        decrypt_bad = self.vault.verify(id, cipher_v2, 1)
        self.assertNotEqual(data_b64, decrypt_bad.result.plain_text)

        # Decrypt wrong id
        def decrypt_bad_id():
            resp = self.vault.decrypt("thisisnotandid", cipher_v2, 2)

        # This should fail because it's trying to verify with wrong id
        self.assertRaises(pexc.PangeaAPIException, decrypt_bad_id)

        # Revoke key
        revoke_resp = self.vault.revoke(id)
        self.assertEqual(id, revoke_resp.result.id)

        # Decrypt after revoked. allow_revoked = false
        def verify_revoked_not_allowed():
            resp = self.vault.decrypt(id, cipher_v2, 2, allow_revoked=False)

        # This should fail because it's trying to verify with wrong id
        self.assertRaises(pexc.PangeaAPIException, verify_revoked_not_allowed)

        # Decrypt after revoked. allow_revoked = true
        decrypt1_revoked_resp = self.vault.decrypt(id, cipher_v1, 1)
        self.assertEqual(data_b64, decrypt1_revoked_resp.result.plain_text)

    def signing_cycle(self, id):
        data = "thisisamessagetosign"
        # Sign 1
        sign1_resp = self.vault.sign(id, data)
        self.assertEqual(id, sign1_resp.result.id)
        self.assertEqual(1, sign1_resp.result.version)
        signature_v1 = sign1_resp.result.signature
        self.assertIsNotNone(signature_v1)

        # Rotate
        rotate_resp = self.vault.rotate_key(id)
        self.assertEqual(2, rotate_resp.result.version)
        self.assertEqual(id, rotate_resp.result.id)

        # Sign 2
        sign2_resp = self.vault.sign(id, data)
        self.assertEqual(id, sign2_resp.result.id)
        self.assertEqual(2, sign2_resp.result.version)
        signature_v2 = sign2_resp.result.signature
        self.assertIsNotNone(signature_v2)

        # Verify 1
        try:
            verify1_resp = self.vault.verify(id, data, signature_v1, 1)
        except pexc.PangeaAPIException as e:
            print(f"Response: {e.response}")
            if e.errors:
                print("Error details: ")
                for ef in e.errors:
                    print(f"\t {ef.detail}")
        self.assertEqual(id, verify1_resp.result.id)
        self.assertEqual(1, verify1_resp.result.version)
        self.assertTrue(verify1_resp.result.signature_verified)

        # Verify 2
        verify2_resp = self.vault.verify(id, data, signature_v2, 2)
        self.assertEqual(id, verify2_resp.result.id)
        self.assertEqual(2, verify2_resp.result.version)
        self.assertTrue(verify2_resp.result.signature_verified)

        # Verify default version
        verify_default_resp = self.vault.verify(id, data, signature_v2)
        self.assertEqual(id, verify_default_resp.result.id)
        self.assertEqual(2, verify_default_resp.result.version)
        self.assertTrue(verify_default_resp.result.signature_verified)

        # Verify wrong version
        def verify_wrong_version():
            resp = self.vault.verify(id, data, signature_v2, 1)

        # This should fail because it's trying to verify with wrong version
        self.assertRaises(pexc.PangeaAPIException, verify_wrong_version)

        # Verify wrong id
        def verify_bad_id():
            resp = self.vault.verify("thisisnotandid", data, signature_v2, 2)

        # This should fail because it's trying to verify with wrong id
        self.assertRaises(pexc.PangeaAPIException, verify_bad_id)

        # Verify wrong signature
        def verify_bad_signature():
            resp = self.vault.verify(id, data, "thisisnotasignature", 2)

        # This should fail because it's trying to verify with wrong signature
        self.assertRaises(pexc.PangeaAPIException, verify_bad_signature)

        # Verify wrong data
        def verify_bad_data():
            resp = self.vault.verify(id, "thisisnottheoriginaldata", signature_v2, 2)

        # This should fail because it's trying to verify with wrong data
        self.assertRaises(pexc.PangeaAPIException, verify_bad_data)

        # Revoke key
        revoke_resp = self.vault.revoke(id)
        self.assertEqual(id, revoke_resp.result.id)

        # Verify after revoked. allow_revoked = false
        def verify_revoked_not_allowed():
            resp = self.vault.verify(id, data, signature_v2, 2, allow_revoked=False)

        # This should fail because it's trying to verify with wrong id
        self.assertRaises(pexc.PangeaAPIException, verify_revoked_not_allowed)

        # Verify after revoked. allow_revoked = true
        verify1_revoked_resp = self.vault.verify(id, data, signature_v1, 1)
        self.assertEqual(id, verify1_revoked_resp.result.id)
        self.assertEqual(1, verify1_revoked_resp.result.version)
        self.assertTrue(verify1_revoked_resp.result.signature_verified)

    def test_aes_create(self):
        success = 0
        failed = 0
        logger = setup_logger(LOG_PATH, THIS_FUNCTION_NAME(), LOG_LEVEL, LOG_FORMATTER)
        logger.critical("Starting...")
        for parameters in self.key_param_comb:
            try:
                response = self.vault.create_symmetric(algorithm=KeyAlgorithm.AES, **parameters)
                logger.debug(f"\nSymmetric parameters: {parameters}")
                logger.debug(f"Success result: {response.result}")
                self.create_symmetric_check_response(response, parameters)
                success += 1
            except pexc.PangeaAPIException as e:
                if parameters["managed"] is True and parameters["stored"] is False:
                    logger.debug(f"\n Success failed with symmetric parameters: {parameters}")
                    success += 1
                else:
                    failed += 1
                    logger.critical("\nSymmetric parameters: ", parameters)
                    logger.critical(f"Exception result: {e}")
                    logger.error(f"Response: {e.response}")
                    if e.errors:
                        logger.warning("Error details: ")
                        for ef in e.errors:
                            logger.warning(f"\t {ef.detail}")

        logger.critical(f"\nFinal summary. Success: {success}. Failed: {failed}")

    def test_ed25519_create_signing(self):
        success = 0
        failed = 0
        logger = setup_logger(LOG_PATH, THIS_FUNCTION_NAME(), LOG_LEVEL, LOG_FORMATTER)
        logger.critical("Starting...")
        for parameters in self.key_param_comb:
            try:
                response = self.vault.create_asymmetric(
                    algorithm=KeyPairAlgorithm.Ed25519, purpose=KeyPairPurpose.SIGNING, **parameters
                )
                logger.debug(f"\nAsymmetric parameters: {parameters}")
                logger.debug(f"Success result: {response.result}")
                self.create_asymmetric_check_response(response, parameters)
                success += 1
            except pexc.PangeaAPIException as e:
                if parameters["managed"] is True and parameters["stored"] is False:
                    logger.debug(f"\n Success failed with asymmetric parameters: {parameters}")
                    success += 1
                else:
                    failed += 1
                    logger.critical(f"\nAsymmetric parameters: {parameters}")
                    logger.critical(f"Exception result: {e}")
                    logger.error(f"Response: {e.response}")
                    if e.errors:
                        logger.info("Error details: ")
                        for ef in e.errors:
                            logger.info(f"\t {ef.detail}")

        logger.critical(f"\nFinal summary. Success: {success}. Failed: {failed}")

    def test_ed25519_create_encryption(self):
        success = 0
        failed = 0
        logger = setup_logger(LOG_PATH, THIS_FUNCTION_NAME(), LOG_LEVEL, LOG_FORMATTER)
        logger.critical("Starting...")
        for parameters in self.key_param_comb:
            try:
                response = self.vault.create_asymmetric(
                    algorithm=KeyPairAlgorithm.Ed25519, purpose=KeyPairPurpose.ENCRYPTION, **parameters
                )
                logger.debug(f"\nAsymmetric parameters: {parameters}")
                logger.debug(f"Success result: {response.result}")
                self.create_asymmetric_check_response(response, parameters)
                success += 1
            except pexc.PangeaAPIException as e:
                if parameters["managed"] is True and parameters["stored"] is False:
                    logger.debug(f"\n Success failed with asymmetric parameters: {parameters}")
                    success += 1
                else:
                    failed += 1
                    logger.critical(f"\nAsymmetric parameters: {parameters}")
                    logger.critical(f"Exception result: {e}")
                    logger.error(f"Response: {e.response}")
                    if e.errors:
                        logger.info("Error details: ")
                        for ef in e.errors:
                            logger.info(f"\t {ef.detail}")

        logger.critical(f"\nFinal summary. Success: {success}. Failed: {failed}")

    # FIXME: BUG THAT SHOULD BE FIXED
    def test_create_key_aes_managed_but_no_stored(self):
        logger = setup_logger(LOG_PATH, THIS_FUNCTION_NAME(), LOG_LEVEL, LOG_FORMATTER)
        try:
            response = self.vault.create_symmetric(algorithm=KeyAlgorithm.AES, managed=True, store=False)
            logger.debug(f"Success result: {response.result}")
            logger.debug(f"Success response: {response}")
            self.assertTrue(False)
        except pexc.PangeaAPIException as e:
            print("Remove this test. Bug was fixed...")
            logger.critical(f"Exception result: {e}")
            logger.error(f"Response: {e.response}")
            if e.errors:
                logger.warning("Error details: ")
                for ef in e.errors:
                    logger.warning(f"\t {ef.detail}")

    def test_secret_create(self):
        success = 0
        failed = 0
        logger = setup_logger(LOG_PATH, THIS_FUNCTION_NAME(), LOG_LEVEL, LOG_FORMATTER)
        logger.critical("Starting...")
        for parameters in self.common_param_comb:
            try:
                response = self.vault.create_secret(**parameters)
                logger.debug(f"\nSecret parameters: {parameters}")
                logger.debug(f"Success result: {response.result}")
                self.create_secret_check_response(response)
                success += 1
            except pexc.PangeaAPIException as e:
                failed += 1
                logger.critical(f"\nSecret parameters: {parameters}")
                logger.critical(f"Exception result: {e}")
                logger.error(f"Response: {e.response}")
                if e.errors:
                    logger.info("Error details: ")
                    for ef in e.errors:
                        logger.info(f"\t {ef.detail}")

        logger.critical(f"\nFinal summary. Success: {success}. Failed: {failed}")

    def test_ed25519_signing_life_cycle(self):
        # Create
        create_resp = self.vault.create_asymmetric(
            algorithm=KeyPairAlgorithm.Ed25519, purpose=KeyPairPurpose.SIGNING, managed=True, store=True
        )
        id = create_resp.result.id
        self.assertIsNotNone(id)
        self.assertEqual(1, create_resp.result.version)
        self.signing_cycle(id)

    def test_ed25519_encrypting_life_cycle(self):
        # Create
        create_resp = self.vault.create_asymmetric(
            algorithm=KeyPairAlgorithm.Ed25519, purpose=KeyPairPurpose.ENCRYPTION, managed=True, store=True
        )
        id = create_resp.result.id
        self.assertIsNotNone(id)
        self.assertEqual(1, create_resp.result.version)
        self.encrypting_cycle(id)

    def test_aes_encrypting_life_cycle(self):
        # Create
        create_resp = self.vault.create_symmetric(algorithm=KeyAlgorithm.AES, managed=True, store=True)
        id = create_resp.result.id
        self.assertIsNotNone(id)
        self.assertEqual(1, create_resp.result.version)
        self.encrypting_cycle(id)

    def test_ed25519_create_store_signing_life_cycle(self):
        # Create
        create_resp = self.vault.create_asymmetric(
            algorithm=KeyPairAlgorithm.Ed25519, purpose=KeyPairPurpose.SIGNING, managed=False, store=False
        )

        pub_key = create_resp.result.public_key
        priv_key = create_resp.result.private_key
        self.assertIsNone(create_resp.result.id)
        self.assertIsNotNone(pub_key)
        self.assertIsNotNone(priv_key)

        store_resp = self.vault.store_asymmetric(
            algorithm=KeyPairAlgorithm.Ed25519,
            purpose=KeyPairPurpose.SIGNING,
            public_key=pub_key,
            private_key=priv_key,
            managed=False,
        )

        id = store_resp.result.id
        self.assertIsNotNone(id)
        self.assertEqual(pub_key, store_resp.result.public_key)
        self.assertEqual(priv_key, store_resp.result.private_key)
        self.assertEqual(1, store_resp.result.version)
        self.signing_cycle(id)

    def test_ed25519_create_store_encrypting_life_cycle(self):
        # Create
        create_resp = self.vault.create_asymmetric(
            algorithm=KeyPairAlgorithm.Ed25519, purpose=KeyPairPurpose.ENCRYPTION, managed=False, store=False
        )
        pub_key = create_resp.result.public_key
        priv_key = create_resp.result.private_key
        self.assertIsNone(create_resp.result.id)
        self.assertIsNotNone(pub_key)
        self.assertIsNotNone(priv_key)

        store_resp = self.vault.store_asymmetric(
            algorithm=KeyPairAlgorithm.Ed25519,
            purpose=KeyPairPurpose.ENCRYPTION,
            public_key=create_resp.result.public_key,
            private_key=create_resp.result.private_key,
            managed=False,
        )

        id = store_resp.result.id
        self.assertIsNotNone(id)
        self.assertEqual(pub_key, store_resp.result.public_key)
        self.assertEqual(priv_key, store_resp.result.private_key)
        self.assertEqual(1, store_resp.result.version)
        self.encrypting_cycle(id)

    def test_aes_create_store_encrypting_life_cycle(self):
        # Create
        algorithm = KeyAlgorithm.AES
        create_resp = self.vault.create_symmetric(algorithm=algorithm, managed=False, store=False)
        self.assertIsNone(create_resp.result.id)
        self.assertIsNotNone(create_resp.result.key)
        self.assertEqual(1, create_resp.result.version)

        key = create_resp.result.key
        store_resp = self.vault.store_symmetric(algorithm=algorithm, key=key, managed=False)
        id = store_resp.result.id
        self.assertIsNotNone(id)
        self.assertEqual(1, store_resp.result.version)
        self.assertEqual(key, store_resp.result.key)

        self.encrypting_cycle(id)

    def test_secret_life_cycle(self):
        create_resp = self.vault.create_secret()
        id = create_resp.result.id
        secret_v1 = create_resp.result.secret
        self.assertIsNotNone(id)
        self.assertEqual(1, create_resp.result.version)

        rotate_resp = self.vault.rotate_secret(id)
        secret_v2 = rotate_resp.result.secret
        self.assertEqual(id, rotate_resp.result.id)
        self.assertEqual(2, rotate_resp.result.version)
        self.assertNotEqual(secret_v1, secret_v2)

        retrieve_resp = self.vault.retrieve(id)
        self.assertEqual(secret_v2, retrieve_resp.result.secret)

        try:
            revoke_resp = self.vault.revoke(id)
        except pexc.PangeaAPIException as e:
            print(f"Exception result: {e}")
            print(f"Response: {e.response}")
            if e.errors:
                print("Error details: ")
                for ef in e.errors:
                    print(f"\t {ef.detail}")

        print(revoke_resp)
        self.assertEqual(id, revoke_resp.result.id)

        def retrieve_revoked_secret():
            self.vault.retrieve(id)

        # This should fail because secret was revoked
        self.assertRaises(pexc.PangeaAPIException, retrieve_revoked_secret)

    def test_list(self):
        # FIXME: Update once we defined filters to list
        list_resp = self.vault.list()
