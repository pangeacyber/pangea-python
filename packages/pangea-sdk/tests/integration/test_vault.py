import datetime
import inspect
import json
import random
import unittest
from typing import Dict, List

import pangea.exceptions as pexc
from pangea import PangeaConfig
from pangea.services.vault.models.asymmetric import AsymmetricAlgorithm, KeyPurpose
from pangea.services.vault.models.symmetric import SymmetricAlgorithm
from pangea.services.vault.vault import ItemType, ItemVersionState, Vault
from pangea.tools import TestEnvironment, get_test_domain, get_test_token, logger_set_pangea_config
from pangea.utils import format_datetime, str2str_b64

TIME = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
THIS_FUNCTION_NAME = lambda: inspect.stack()[1][3]
FOLDER_VALUE = f"/test_key_folder/{TIME}/"
METADATA_VALUE = {"test": "True", "field1": "value1", "field2": "value2"}
TAGS_VALUE = ["test", "symmetric"]
ROTATION_FREQUENCY_VALUE = "1d"
ROTATION_STATE_VALUE = ItemVersionState.DEACTIVATED
EXPIRATION_VALUE = datetime.datetime.now() + datetime.timedelta(days=1)
EXPIRATION_VALUE_STR = format_datetime(EXPIRATION_VALUE)
MAX_RANDOM = 1000000
ACTOR = "PythonSDKTest"


def get_random_id() -> str:
    return str(random.randrange(1, MAX_RANDOM))


def get_name() -> str:
    caller_name = inspect.stack()[1][3]
    return f"{TIME}_{ACTOR}_{caller_name}_{get_random_id()}"


TEST_ENVIRONMENT = TestEnvironment.LIVE

KEY_ED25519 = {
    "algorithm": AsymmetricAlgorithm.Ed25519,
    "private_key": "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIGthqegkjgddRAn0PWN2FeYC6HcCVQf/Ph9sUbeprTBO\n-----END PRIVATE KEY-----\n",
    "public_key": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAPlGrDliJXUbPc2YWEhFxlL2UbBfLHc3ed1f36FrDtTc=\n-----END PUBLIC KEY-----\n",
}

KEY_AES = {
    "algorithm": SymmetricAlgorithm.AES,
    "key": "oILlp2FUPHWiaqFXl4/1ww==",
}


class TestVault(unittest.TestCase):
    def setUp(self):
        self.token = get_test_token(TEST_ENVIRONMENT)
        domain = get_test_domain(TEST_ENVIRONMENT)
        self.config = PangeaConfig(domain=domain)
        self.vault = Vault(self.token, config=self.config, logger_name="vault")
        logger_set_pangea_config("vault")

    def encrypting_cycle(self, id):
        msg = "thisisamessagetoencrypt"
        data_b64 = str2str_b64(msg)

        # Encrypt 1
        encrypt1_resp = self.vault.encrypt(id, data_b64)

        self.assertEqual(id, encrypt1_resp.result.id)
        self.assertEqual(1, encrypt1_resp.result.version)
        cipher_v1 = encrypt1_resp.result.cipher_text
        self.assertIsNotNone(cipher_v1)

        # Rotate
        rotate_resp = self.vault.key_rotate(id=id, rotation_state=ItemVersionState.SUSPENDED)
        self.assertEqual(2, rotate_resp.result.version)
        self.assertEqual(id, rotate_resp.result.id)

        # Encrypt 2
        encrypt2_resp = self.vault.encrypt(id, data_b64)
        self.assertEqual(id, encrypt2_resp.result.id)
        self.assertEqual(2, encrypt2_resp.result.version)
        cipher_v2 = encrypt2_resp.result.cipher_text
        self.assertIsNotNone(cipher_v2)

        # Decrypt 1
        decrypt1_resp = self.vault.decrypt(id, cipher_v1, 1)
        self.assertEqual(data_b64, decrypt1_resp.result.plain_text)

        # Decrypt 2
        decrypt2_resp = self.vault.decrypt(id, cipher_v2, 2)
        self.assertTrue(data_b64, decrypt2_resp.result.plain_text)

        # Decrypt default version
        decrypt_default_resp = self.vault.decrypt(id, cipher_v2)
        self.assertEqual(data_b64, decrypt_default_resp.result.plain_text)

        # Decrypt wrong version
        # decrypt_bad = self.vault.decrypt(id, cipher_v2, 1)
        # self.assertNotEqual(data_b64, decrypt_bad.result.plain_text)

        # Decrypt wrong id
        with self.assertRaises(pexc.VaultItemNotFound):
            self.vault.decrypt("thisisnotandid", cipher_v2, 2)

        # Desactivate key
        change_state_resp = self.vault.state_change(id, ItemVersionState.DEACTIVATED, version=1)
        self.assertEqual(id, change_state_resp.result.id)

        # Decrypt after deactivated.
        decrypt1_deactivated_resp = self.vault.decrypt(id, cipher_v1, 1)
        self.assertEqual(data_b64, decrypt1_deactivated_resp.result.plain_text)

    def signing_cycle(self, id):
        data = "thisisamessagetosign"
        # Sign 1
        sign1_resp = self.vault.sign(id, data)
        self.assertEqual(id, sign1_resp.result.id)
        self.assertEqual(1, sign1_resp.result.version)
        signature_v1 = sign1_resp.result.signature
        self.assertIsNotNone(signature_v1)

        # Rotate
        rotate_resp = self.vault.key_rotate(id, rotation_state=ItemVersionState.SUSPENDED)
        self.assertEqual(2, rotate_resp.result.version)
        self.assertEqual(id, rotate_resp.result.id)

        # Sign 2
        sign2_resp = self.vault.sign(id, data)
        self.assertEqual(id, sign2_resp.result.id)
        self.assertEqual(2, sign2_resp.result.version)
        signature_v2 = sign2_resp.result.signature
        self.assertIsNotNone(signature_v2)

        # Verify 1
        verify1_resp = self.vault.verify(id, data, signature_v1, 1)
        self.assertEqual(id, verify1_resp.result.id)
        self.assertEqual(1, verify1_resp.result.version)
        self.assertTrue(verify1_resp.result.valid_signature)

        # Verify 2
        verify2_resp = self.vault.verify(id, data, signature_v2, 2)
        self.assertEqual(id, verify2_resp.result.id)
        self.assertEqual(2, verify2_resp.result.version)
        self.assertTrue(verify2_resp.result.valid_signature)

        # Verify default version
        verify_default_resp = self.vault.verify(id, data, signature_v2)
        self.assertEqual(id, verify_default_resp.result.id)
        self.assertEqual(2, verify_default_resp.result.version)
        self.assertTrue(verify_default_resp.result.valid_signature)

        # Verify not existing version
        with self.assertRaises(pexc.VaultItemNotFound):
            self.vault.verify(id, data, signature_v2, 10)

        # Verify wrong id
        with self.assertRaises(pexc.VaultItemNotFound):
            self.vault.verify("thisisnotandid", data, signature_v2, 2)

        # Verify wrong signature
        with self.assertRaises(pexc.PangeaAPIException):
            self.vault.verify(id, data, "thisisnotasignature", 2)

        # Verify wrong data
        with self.assertRaises(pexc.PangeaAPIException):
            self.vault.verify(id, "thisisnotvaliddatax", signature_v2, 2)

        # Deactivate key
        state_change_resp = self.vault.state_change(id, ItemVersionState.DEACTIVATED, version=1)
        self.assertEqual(id, state_change_resp.result.id)

        # Verify after deactivated.
        verify1_deactivated_resp = self.vault.verify(id, data, signature_v1, 1)
        self.assertEqual(id, verify1_deactivated_resp.result.id)
        self.assertEqual(1, verify1_deactivated_resp.result.version)
        self.assertTrue(verify1_deactivated_resp.result.valid_signature)

    def sym_generate_default(self, algorithm: SymmetricAlgorithm, purpose: KeyPurpose) -> str:
        name = get_name()
        response = self.vault.symmetric_generate(algorithm=algorithm, purpose=purpose, name=name)
        self.assertEqual(ItemType.SYMMETRIC_KEY.value, response.result.type)
        self.assertEqual(1, response.result.version)
        self.assertIsNotNone(response.result.id)
        self.assertEqual(algorithm.value, response.result.algorithm)
        return response.result.id

    def sym_generate_all_params(self, algorithm: SymmetricAlgorithm, purpose: KeyPurpose) -> str:
        name = get_name()
        response = self.vault.symmetric_generate(
            algorithm=algorithm,
            purpose=purpose,
            name=name,
            folder=FOLDER_VALUE,
            metadata=METADATA_VALUE,
            tags=TAGS_VALUE,
            rotation_frequency=ROTATION_FREQUENCY_VALUE,
            rotation_state=ROTATION_STATE_VALUE,
            expiration=EXPIRATION_VALUE,
        )
        self.assertEqual(ItemType.SYMMETRIC_KEY.value, response.result.type)
        self.assertEqual(1, response.result.version)
        self.assertIsNotNone(response.result.id)

        response = self.vault.get(id=response.result.id, verbose=True)
        self.assertEqual(ItemType.SYMMETRIC_KEY.value, response.result.type)
        self.assertEqual(0, len(response.result.versions))
        self.assertEqual(1, response.result.current_version.version)
        self.assertEqual(name, response.result.name)
        self.assertEqual(FOLDER_VALUE, response.result.folder)
        self.assertEqual(METADATA_VALUE, response.result.metadata)
        self.assertEqual(TAGS_VALUE, response.result.tags)
        self.assertEqual(ROTATION_FREQUENCY_VALUE, response.result.rotation_frequency)
        self.assertEqual(ROTATION_STATE_VALUE.value, response.result.rotation_state)
        self.assertEqual(EXPIRATION_VALUE_STR, response.result.expiration)
        return response.result.id

    def test_sym_aes_store_default(self):
        name = name = get_name()
        response = self.vault.symmetric_store(**KEY_AES, purpose=KeyPurpose.ENCRYPTION, name=name)
        self.assertEqual(ItemType.SYMMETRIC_KEY.value, response.result.type)
        self.assertEqual(1, response.result.version)
        self.assertIsNotNone(response.result.id)

    def test_sym_aes_store_all_params(self):
        name = name = get_name()
        response = self.vault.symmetric_store(
            name=name,
            folder=FOLDER_VALUE,
            metadata=METADATA_VALUE,
            tags=TAGS_VALUE,
            rotation_frequency=ROTATION_FREQUENCY_VALUE,
            rotation_state=ROTATION_STATE_VALUE,
            expiration=EXPIRATION_VALUE,
            purpose=KeyPurpose.ENCRYPTION,
            **KEY_AES,
        )
        self.assertEqual(ItemType.SYMMETRIC_KEY.value, response.result.type)
        self.assertEqual(1, response.result.version)
        self.assertIsNotNone(response.result.id)

        response = self.vault.get(id=response.result.id, verbose=True)
        self.assertEqual(ItemType.SYMMETRIC_KEY.value, response.result.type)
        self.assertEqual(0, len(response.result.versions))
        self.assertEqual(1, response.result.current_version.version)
        self.assertEqual(name, response.result.name)
        self.assertEqual(FOLDER_VALUE, response.result.folder)
        self.assertEqual(METADATA_VALUE, response.result.metadata)
        self.assertEqual(TAGS_VALUE, response.result.tags)
        self.assertEqual(ROTATION_FREQUENCY_VALUE, response.result.rotation_frequency)
        self.assertEqual(ROTATION_STATE_VALUE.value, response.result.rotation_state)
        self.assertEqual(EXPIRATION_VALUE_STR, response.result.expiration)

    def test_asym_ed25519_store_default(self):
        name = name = get_name()
        response = self.vault.asymmetric_store(**KEY_ED25519, purpose=KeyPurpose.SIGNING, name=name)
        self.assertEqual(ItemType.ASYMMETRIC_KEY.value, response.result.type)
        self.assertEqual(1, response.result.version)
        self.assertIsNotNone(response.result.id)

    def test_asym_ed25519_store_all_params(self):
        name = name = get_name()
        response = self.vault.asymmetric_store(
            name=name,
            folder=FOLDER_VALUE,
            metadata=METADATA_VALUE,
            tags=TAGS_VALUE,
            rotation_frequency=ROTATION_FREQUENCY_VALUE,
            rotation_state=ROTATION_STATE_VALUE,
            expiration=EXPIRATION_VALUE,
            purpose=KeyPurpose.SIGNING,
            **KEY_ED25519,
        )
        self.assertEqual(ItemType.ASYMMETRIC_KEY.value, response.result.type)
        self.assertEqual(1, response.result.version)
        self.assertIsNotNone(response.result.id)

        response = self.vault.get(id=response.result.id, verbose=True)
        self.assertEqual(ItemType.ASYMMETRIC_KEY.value, response.result.type)
        self.assertEqual(0, len(response.result.versions))
        self.assertEqual(1, response.result.current_version.version)
        self.assertEqual(name, response.result.name)
        self.assertEqual(FOLDER_VALUE, response.result.folder)
        self.assertEqual(METADATA_VALUE, response.result.metadata)
        self.assertEqual(TAGS_VALUE, response.result.tags)
        self.assertEqual(ROTATION_FREQUENCY_VALUE, response.result.rotation_frequency)
        self.assertEqual(ROTATION_STATE_VALUE.value, response.result.rotation_state)
        self.assertEqual(EXPIRATION_VALUE_STR, response.result.expiration)

    def asym_generate_default(self, algorithm: AsymmetricAlgorithm, purpose: KeyPurpose) -> str:
        name = get_name()
        response = self.vault.asymmetric_generate(algorithm=algorithm, purpose=purpose, name=name)
        self.assertEqual(ItemType.ASYMMETRIC_KEY.value, response.result.type)
        self.assertEqual(1, response.result.version)
        self.assertIsNotNone(response.result.id)
        self.assertEqual(algorithm.value, response.result.algorithm)
        return response.result.id

    def asym_generate_all_params(self, algorithm: AsymmetricAlgorithm, purpose: KeyPurpose) -> str:
        name = get_name()
        response = self.vault.asymmetric_generate(
            algorithm=algorithm,
            purpose=purpose,
            name=name,
            folder=FOLDER_VALUE,
            metadata=METADATA_VALUE,
            tags=TAGS_VALUE,
            rotation_frequency=ROTATION_FREQUENCY_VALUE,
            rotation_state=ROTATION_STATE_VALUE,
            expiration=EXPIRATION_VALUE,
        )
        self.assertEqual(ItemType.ASYMMETRIC_KEY.value, response.result.type)
        self.assertEqual(1, response.result.version)
        self.assertIsNotNone(response.result.id)
        self.assertEqual(algorithm.value, response.result.algorithm)

        response = self.vault.get(id=response.result.id, verbose=True)
        self.assertEqual(ItemType.ASYMMETRIC_KEY.value, response.result.type)
        self.assertEqual(0, len(response.result.versions))
        self.assertEqual(1, response.result.current_version.version)
        self.assertEqual(name, response.result.name)
        self.assertEqual(FOLDER_VALUE, response.result.folder)
        self.assertEqual(METADATA_VALUE, response.result.metadata)
        self.assertEqual(TAGS_VALUE, response.result.tags)
        self.assertEqual(ROTATION_FREQUENCY_VALUE, response.result.rotation_frequency)
        self.assertEqual(ROTATION_STATE_VALUE.value, response.result.rotation_state)
        self.assertEqual(EXPIRATION_VALUE_STR, response.result.expiration)
        return response.result.id

    def jwt_sym_signing_cycle(self, id):
        data = {"message": "message to sign", "data": "Some extra data"}
        payload = json.dumps(data)

        # Sign 1
        sign1_resp = self.vault.jwt_sign(id, payload)
        jws_v1 = sign1_resp.result.jws
        self.assertIsNotNone(jws_v1)

        # Rotate
        rotate_resp = self.vault.key_rotate(id, ItemVersionState.SUSPENDED)
        self.assertEqual(2, rotate_resp.result.version)
        self.assertEqual(id, rotate_resp.result.id)

        # Sign 2
        sign2_resp = self.vault.jwt_sign(id, payload)
        jws_v2 = sign2_resp.result.jws
        self.assertIsNotNone(jws_v2)

        # Verify 1
        verify1_resp = self.vault.jwt_verify(jws_v1)
        self.assertTrue(verify1_resp.result.valid_signature)

        # Verify 2
        verify2_resp = self.vault.jwt_verify(jws_v2)
        self.assertTrue(verify2_resp.result.valid_signature)

        # Deactivate key
        state_change_resp = self.vault.state_change(id, ItemVersionState.DEACTIVATED, version=1)
        self.assertEqual(id, state_change_resp.result.id)

        # Verify after deactivated.
        verify1_deactivated_resp = self.vault.jwt_verify(jws_v1)
        self.assertTrue(verify1_deactivated_resp.result.valid_signature)

    def jwt_asym_signing_cycle(self, id):
        data = {"message": "message to sign", "data": "Some extra data"}
        payload = json.dumps(data)

        # Sign 1
        sign1_resp = self.vault.jwt_sign(id, payload)
        jws_v1 = sign1_resp.result.jws
        self.assertIsNotNone(jws_v1)

        # Rotate
        rotate_resp = self.vault.key_rotate(id, ItemVersionState.SUSPENDED)
        self.assertEqual(2, rotate_resp.result.version)
        self.assertEqual(id, rotate_resp.result.id)

        # Sign 2
        sign2_resp = self.vault.jwt_sign(id, payload)
        jws_v2 = sign2_resp.result.jws
        self.assertIsNotNone(jws_v2)

        # Verify 1
        verify1_resp = self.vault.jwt_verify(jws_v1)
        self.assertTrue(verify1_resp.result.valid_signature)

        # Verify 2
        verify2_resp = self.vault.jwt_verify(jws_v2)
        self.assertTrue(verify2_resp.result.valid_signature)

        # Get default
        get_resp = self.vault.jwk_get(id)
        self.assertEqual(1, len(get_resp.result.keys))

        # Get version 1
        get_resp = self.vault.jwk_get(id, 1)
        self.assertEqual(1, len(get_resp.result.keys))

        # Get all
        get_resp = self.vault.jwk_get(id, "all")
        self.assertEqual(2, len(get_resp.result.keys))

        # Get version -1
        get_resp = self.vault.jwk_get(id, "-1")
        self.assertEqual(2, len(get_resp.result.keys))

        # Deactivate key
        state_change_resp = self.vault.state_change(id, ItemVersionState.DEACTIVATED, version=1)
        self.assertEqual(id, state_change_resp.result.id)

        # Verify after deactivated.
        verify1_deactivated_resp = self.vault.jwt_verify(jws_v1)
        self.assertTrue(verify1_deactivated_resp.result.valid_signature)

    def test_generate_asym_signing_all_params(self):
        algorithms = [
            AsymmetricAlgorithm.Ed25519,
            AsymmetricAlgorithm.RSA,
        ]
        purpose = KeyPurpose.SIGNING
        for a in algorithms:
            id = self.asym_generate_all_params(algorithm=a, purpose=purpose)
            self.vault.delete(id=id)

    def test_generate_asym_encrypting_all_params(self):
        algorithms = [
            AsymmetricAlgorithm.RSA,
        ]
        purpose = KeyPurpose.ENCRYPTION
        for a in algorithms:
            id = self.asym_generate_all_params(algorithm=a, purpose=purpose)
            self.vault.delete(id=id)

    def test_generate_sym_encrypting_all_params(self):
        algorithms = [
            SymmetricAlgorithm.AES,
        ]
        purpose = KeyPurpose.ENCRYPTION
        for a in algorithms:
            id = self.sym_generate_all_params(algorithm=a, purpose=purpose)
            self.vault.delete(id=id)

    def test_asym_encripting_life_cycle(self):
        algorithms = [
            AsymmetricAlgorithm.RSA,
        ]
        purpose = KeyPurpose.ENCRYPTION
        for algorithm in algorithms:
            id = self.asym_generate_default(algorithm=algorithm, purpose=purpose)
            try:
                self.encrypting_cycle(id)
                self.vault.delete(id=id)
            except pexc.PangeaAPIException as e:
                print(f"Failed test_asym_encripting_life_cycle with {algorithm}")
                print(e)
                self.vault.delete(id=id)
                self.assertTrue(False)

    def test_asym_signing_life_cycle(self):
        algorithms = [
            AsymmetricAlgorithm.Ed25519,
            AsymmetricAlgorithm.RSA,
        ]
        purpose = KeyPurpose.SIGNING
        for algorithm in algorithms:
            id = self.asym_generate_default(algorithm=algorithm, purpose=purpose)
            try:
                self.signing_cycle(id)
                self.vault.delete(id=id)
            except pexc.PangeaAPIException as e:
                print(f"Failed {THIS_FUNCTION_NAME()} with {algorithm}")
                print(e)
                self.vault.delete(id=id)
                self.assertTrue(False)

    def test_sym_encripting_life_cycle(self):
        algorithms = [
            SymmetricAlgorithm.AES,
        ]
        purpose = KeyPurpose.ENCRYPTION
        for algorithm in algorithms:
            id = self.sym_generate_default(algorithm=algorithm, purpose=purpose)
            try:
                self.encrypting_cycle(id)
                self.vault.delete(id=id)
            except pexc.PangeaAPIException as e:
                print(f"Failed {THIS_FUNCTION_NAME()} with {algorithm}")
                print(e)
                self.vault.delete(id=id)
                self.assertTrue(False)

    def test_secret_life_cycle(self):
        name = name = get_name()
        create_resp = self.vault.secret_store(secret="hello world", name=name)
        id = create_resp.result.id
        secret_v1 = create_resp.result.secret
        self.assertIsNotNone(id)
        self.assertEqual(1, create_resp.result.version)
        self.assertEqual(ItemType.SECRET, create_resp.result.type)

        rotate_resp = self.vault.secret_rotate(id=id, secret="new hello world")
        secret_v2 = rotate_resp.result.secret
        self.assertEqual(id, rotate_resp.result.id)
        self.assertEqual(2, rotate_resp.result.version)
        self.assertEqual(ItemType.SECRET, rotate_resp.result.type)
        self.assertNotEqual(secret_v1, secret_v2)

        get_resp = self.vault.get(id)
        self.assertEqual(0, len(get_resp.result.versions))
        self.assertEqual(2, get_resp.result.current_version.version)
        self.assertEqual(secret_v2, get_resp.result.current_version.secret)
        self.assertEqual(ItemType.SECRET, get_resp.result.type)

        state_change_resp = self.vault.state_change(id, ItemVersionState.DEACTIVATED, version=2)
        self.assertEqual(id, state_change_resp.result.id)

        # This should fail because secret was deactivated
        get_resp = self.vault.get(id)
        self.assertEqual(id, get_resp.result.id)
        self.assertEqual(0, len(get_resp.result.versions))
        self.assertEqual(ItemVersionState.DEACTIVATED.value, get_resp.result.current_version.state)

    def test_jwt_asym_life_cycle(self):
        # Create
        algorithms = [
            AsymmetricAlgorithm.ES256,
            AsymmetricAlgorithm.ES384,
            AsymmetricAlgorithm.ES512,
        ]
        purpose = KeyPurpose.JWT
        for algorithm in algorithms:
            id = self.asym_generate_default(algorithm=algorithm, purpose=purpose)
            try:
                self.jwt_asym_signing_cycle(id)
                self.vault.delete(id=id)
            except pexc.PangeaAPIException as e:
                print(f"Failed {THIS_FUNCTION_NAME()} with {algorithm}")
                print(e)
                self.vault.delete(id=id)
                self.assertTrue(False)

    def test_jwt_sym_life_cycle(self):
        # Create
        algorithms = [
            SymmetricAlgorithm.HS256,
            SymmetricAlgorithm.HS384,
            SymmetricAlgorithm.HS512,
        ]
        purpose = KeyPurpose.JWT
        for algorithm in algorithms:
            id = self.sym_generate_default(algorithm=algorithm, purpose=purpose)
            try:
                self.jwt_sym_signing_cycle(id)
                self.vault.delete(id=id)
            except pexc.PangeaAPIException as e:
                print(f"Failed {THIS_FUNCTION_NAME()} with {algorithm}")
                print(e)
                self.vault.delete(id=id)
                self.assertTrue(False)
