import datetime
import inspect
import json
import random
import unittest

import pangea.exceptions as pe
from pangea import PangeaConfig
from pangea.asyncio.services.vault import VaultAsync
from pangea.services.vault.models.asymmetric import AsymmetricAlgorithm, KeyPurpose
from pangea.services.vault.models.symmetric import SymmetricAlgorithm
from pangea.services.vault.vault import ItemType, ItemVersionState
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


class TestVault(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.token = get_test_token(TEST_ENVIRONMENT)
        domain = get_test_domain(TEST_ENVIRONMENT)
        self.config = PangeaConfig(domain=domain, custom_user_agent="sdk-test")
        self.vault = VaultAsync(self.token, config=self.config, logger_name="vault")
        logger_set_pangea_config("vault")

    async def asyncTearDown(self):
        await self.vault.close()

    async def encrypting_cycle(self, id):
        msg = "thisisamessagetoencrypt"
        data_b64 = str2str_b64(msg)

        # Encrypt 1
        encrypt1_resp = await self.vault.encrypt(id, data_b64)

        self.assertEqual(id, encrypt1_resp.result.id)
        self.assertEqual(1, encrypt1_resp.result.version)
        cipher_v1 = encrypt1_resp.result.cipher_text
        self.assertIsNotNone(cipher_v1)

        # Rotate
        rotate_resp = await self.vault.key_rotate(id=id, rotation_state=ItemVersionState.SUSPENDED)
        self.assertEqual(2, rotate_resp.result.version)
        self.assertEqual(id, rotate_resp.result.id)

        # Encrypt 2
        encrypt2_resp = await self.vault.encrypt(id, data_b64)
        self.assertEqual(id, encrypt2_resp.result.id)
        self.assertEqual(2, encrypt2_resp.result.version)
        cipher_v2 = encrypt2_resp.result.cipher_text
        self.assertIsNotNone(cipher_v2)

        # Decrypt 1
        decrypt1_resp = await self.vault.decrypt(id, cipher_v1, 1)
        self.assertEqual(data_b64, decrypt1_resp.result.plain_text)

        # Decrypt 2
        decrypt2_resp = await self.vault.decrypt(id, cipher_v2, 2)
        self.assertTrue(data_b64, decrypt2_resp.result.plain_text)

        # Update
        update_resp = await self.vault.update(id, folder="updated")
        self.assertEqual(id, update_resp.result.id)

        # Decrypt default version
        decrypt_default_resp = await self.vault.decrypt(id, cipher_v2)
        self.assertEqual(data_b64, decrypt_default_resp.result.plain_text)

        # Decrypt wrong version
        # decrypt_bad = await self.vault.decrypt(id, cipher_v2, 1)
        # self.assertNotEqual(data_b64, decrypt_bad.result.plain_text)

        # Decrypt wrong id
        with self.assertRaises(pe.ValidationException):
            await self.vault.decrypt("thisisnotandid", cipher_v2, 2)

        # Deactivate key
        change_state_resp = await self.vault.state_change(id, ItemVersionState.DEACTIVATED, version=1)
        self.assertEqual(id, change_state_resp.result.id)

        # Decrypt after deactivated.
        decrypt1_deactivated_resp = await self.vault.decrypt(id, cipher_v1, 1)
        self.assertEqual(data_b64, decrypt1_deactivated_resp.result.plain_text)

    async def signing_cycle(self, id):
        msg = "thisisamessagetosign"
        data = str2str_b64(msg)
        # Sign 1
        sign1_resp = await self.vault.sign(id, data)
        self.assertEqual(id, sign1_resp.result.id)
        self.assertEqual(1, sign1_resp.result.version)
        signature_v1 = sign1_resp.result.signature
        self.assertIsNotNone(signature_v1)

        # Rotate
        rotate_resp = await self.vault.key_rotate(id, rotation_state=ItemVersionState.SUSPENDED)
        self.assertEqual(2, rotate_resp.result.version)
        self.assertEqual(id, rotate_resp.result.id)

        # Sign 2
        sign2_resp = await self.vault.sign(id, data)
        self.assertEqual(id, sign2_resp.result.id)
        self.assertEqual(2, sign2_resp.result.version)
        signature_v2 = sign2_resp.result.signature
        self.assertIsNotNone(signature_v2)

        # Verify 1
        verify1_resp = await self.vault.verify(id, data, signature_v1, 1)
        self.assertEqual(id, verify1_resp.result.id)
        self.assertEqual(1, verify1_resp.result.version)
        self.assertTrue(verify1_resp.result.valid_signature)

        # Verify 2
        verify2_resp = await self.vault.verify(id, data, signature_v2, 2)
        self.assertEqual(id, verify2_resp.result.id)
        self.assertEqual(2, verify2_resp.result.version)
        self.assertTrue(verify2_resp.result.valid_signature)

        # Verify default version
        verify_default_resp = await self.vault.verify(id, data, signature_v2)
        self.assertEqual(id, verify_default_resp.result.id)
        self.assertEqual(2, verify_default_resp.result.version)
        self.assertTrue(verify_default_resp.result.valid_signature)

        # Update
        update_resp = await self.vault.update(id, folder="updated")
        self.assertEqual(id, update_resp.result.id)

        # Verify not existing version
        with self.assertRaises(pe.PangeaAPIException):
            await self.vault.verify(id, data, signature_v2, 10)

        # Verify wrong id
        with self.assertRaises(pe.ValidationException):
            await self.vault.verify("thisisnotandid", data, signature_v2, 2)

        # Verify wrong signature
        with self.assertRaises(pe.PangeaAPIException):
            await self.vault.verify(id, data, "thisisnotasignature", 2)

        # Verify wrong data
        with self.assertRaises(pe.PangeaAPIException):
            await self.vault.verify(id, "thisisnotvaliddatax", signature_v2, 2)

        # Deactivate key
        state_change_resp = await self.vault.state_change(id, ItemVersionState.DEACTIVATED, version=1)
        self.assertEqual(id, state_change_resp.result.id)

        # Verify after deactivated.
        verify1_deactivated_resp = await self.vault.verify(id, data, signature_v1, 1)
        self.assertEqual(id, verify1_deactivated_resp.result.id)
        self.assertEqual(1, verify1_deactivated_resp.result.version)
        self.assertTrue(verify1_deactivated_resp.result.valid_signature)

    async def sym_generate_default(self, algorithm: SymmetricAlgorithm, purpose: KeyPurpose) -> str:
        name = get_name()
        response = await self.vault.symmetric_generate(algorithm=algorithm, purpose=purpose, name=name)
        self.assertEqual(ItemType.SYMMETRIC_KEY.value, response.result.type)
        self.assertEqual(1, response.result.version)
        self.assertIsNotNone(response.result.id)
        self.assertEqual(algorithm.value, response.result.algorithm)
        return response.result.id

    async def sym_generate_all_params(self, algorithm: SymmetricAlgorithm, purpose: KeyPurpose) -> str:
        name = get_name()
        response = await self.vault.symmetric_generate(
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

        response = await self.vault.get(id=response.result.id, verbose=True)
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

    async def test_sym_aes_store_default(self):
        name = name = get_name()
        response = await self.vault.symmetric_store(**KEY_AES, purpose=KeyPurpose.ENCRYPTION, name=name)
        self.assertEqual(ItemType.SYMMETRIC_KEY.value, response.result.type)
        self.assertEqual(1, response.result.version)
        self.assertIsNotNone(response.result.id)

    async def test_sym_aes_store_all_params(self):
        name = name = get_name()
        response = await self.vault.symmetric_store(
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

        response = await self.vault.get(id=response.result.id, verbose=True)
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

    async def test_asym_ed25519_store_default(self):
        name = name = get_name()
        response = await self.vault.asymmetric_store(**KEY_ED25519, purpose=KeyPurpose.SIGNING, name=name)
        self.assertEqual(ItemType.ASYMMETRIC_KEY.value, response.result.type)
        self.assertEqual(1, response.result.version)
        self.assertIsNotNone(response.result.id)

    async def test_asym_ed25519_store_all_params(self):
        name = name = get_name()
        response = await self.vault.asymmetric_store(
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

        response = await self.vault.get(id=response.result.id, verbose=True)
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

    async def asym_generate_default(self, algorithm: AsymmetricAlgorithm, purpose: KeyPurpose) -> str:
        name = get_name()
        response = await self.vault.asymmetric_generate(algorithm=algorithm, purpose=purpose, name=name)
        self.assertEqual(ItemType.ASYMMETRIC_KEY.value, response.result.type)
        self.assertEqual(1, response.result.version)
        self.assertIsNotNone(response.result.id)
        self.assertEqual(algorithm.value, response.result.algorithm)
        return response.result.id

    async def asym_generate_all_params(self, algorithm: AsymmetricAlgorithm, purpose: KeyPurpose) -> str:
        name = get_name()
        response = await self.vault.asymmetric_generate(
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

        response = await self.vault.get(id=response.result.id, verbose=True)
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

    async def jwt_sym_signing_cycle(self, id):
        data = {"message": "message to sign", "data": "Some extra data"}
        payload = json.dumps(data)

        # Sign 1
        sign1_resp = await self.vault.jwt_sign(id, payload)
        jws_v1 = sign1_resp.result.jws
        self.assertIsNotNone(jws_v1)

        # Rotate
        rotate_resp = await self.vault.key_rotate(id, ItemVersionState.SUSPENDED)
        self.assertEqual(2, rotate_resp.result.version)
        self.assertEqual(id, rotate_resp.result.id)

        # Sign 2
        sign2_resp = await self.vault.jwt_sign(id, payload)
        jws_v2 = sign2_resp.result.jws
        self.assertIsNotNone(jws_v2)

        # Verify 1
        verify1_resp = await self.vault.jwt_verify(jws_v1)
        self.assertTrue(verify1_resp.result.valid_signature)

        # Verify 2
        verify2_resp = await self.vault.jwt_verify(jws_v2)
        self.assertTrue(verify2_resp.result.valid_signature)

        # Update
        update_resp = await self.vault.update(id, folder="updated")
        self.assertEqual(id, update_resp.result.id)

        # Deactivate key
        state_change_resp = await self.vault.state_change(id, ItemVersionState.DEACTIVATED, version=1)
        self.assertEqual(id, state_change_resp.result.id)

        # Verify after deactivated.
        verify1_deactivated_resp = await self.vault.jwt_verify(jws_v1)
        self.assertTrue(verify1_deactivated_resp.result.valid_signature)

    async def jwt_asym_signing_cycle(self, id):
        data = {"message": "message to sign", "data": "Some extra data"}
        payload = json.dumps(data)

        # Sign 1
        sign1_resp = await self.vault.jwt_sign(id, payload)
        jws_v1 = sign1_resp.result.jws
        self.assertIsNotNone(jws_v1)

        # Rotate
        rotate_resp = await self.vault.key_rotate(id, ItemVersionState.SUSPENDED)
        self.assertEqual(2, rotate_resp.result.version)
        self.assertEqual(id, rotate_resp.result.id)

        # Sign 2
        sign2_resp = await self.vault.jwt_sign(id, payload)
        jws_v2 = sign2_resp.result.jws
        self.assertIsNotNone(jws_v2)

        # Verify 1
        verify1_resp = await self.vault.jwt_verify(jws_v1)
        self.assertTrue(verify1_resp.result.valid_signature)

        # Verify 2
        verify2_resp = await self.vault.jwt_verify(jws_v2)
        self.assertTrue(verify2_resp.result.valid_signature)

        # Update
        update_resp = await self.vault.update(id, folder="updated")
        self.assertEqual(id, update_resp.result.id)

        # Get default
        get_resp = await self.vault.jwk_get(id)
        self.assertEqual(1, len(get_resp.result.keys))

        # Get version 1
        get_resp = await self.vault.jwk_get(id, "1")
        self.assertEqual(1, len(get_resp.result.keys))

        # Get all
        get_resp = await self.vault.jwk_get(id, "all")
        self.assertEqual(2, len(get_resp.result.keys))

        # Get version -1
        get_resp = await self.vault.jwk_get(id, "-1")
        self.assertEqual(2, len(get_resp.result.keys))

        # Deactivate key
        state_change_resp = await self.vault.state_change(id, ItemVersionState.DEACTIVATED, version=1)
        self.assertEqual(id, state_change_resp.result.id)

        # Verify after deactivated.
        verify1_deactivated_resp = await self.vault.jwt_verify(jws_v1)
        self.assertTrue(verify1_deactivated_resp.result.valid_signature)

    async def test_generate_asym_signing_all_params(self):
        algorithms = [
            AsymmetricAlgorithm.Ed25519,
            AsymmetricAlgorithm.RSA2048_PKCS1V15_SHA256,
        ]
        purpose = KeyPurpose.SIGNING
        for a in algorithms:
            id = await self.asym_generate_all_params(algorithm=a, purpose=purpose)
            await self.vault.delete(id=id)

    async def test_generate_asym_encrypting_all_params(self):
        algorithms = [
            AsymmetricAlgorithm.RSA2048_OAEP_SHA256,
        ]
        purpose = KeyPurpose.ENCRYPTION
        for a in algorithms:
            id = await self.asym_generate_all_params(algorithm=a, purpose=purpose)
            await self.vault.delete(id=id)

    async def test_generate_sym_encrypting_all_params(self):
        algorithms = [
            SymmetricAlgorithm.AES,
        ]
        purpose = KeyPurpose.ENCRYPTION
        for a in algorithms:
            id = await self.sym_generate_all_params(algorithm=a, purpose=purpose)
            await self.vault.delete(id=id)

    async def test_asym_encrypting_life_cycle(self):
        algorithms = [
            AsymmetricAlgorithm.RSA2048_OAEP_SHA256,
        ]
        purpose = KeyPurpose.ENCRYPTION
        for algorithm in algorithms:
            id = await self.asym_generate_default(algorithm=algorithm, purpose=purpose)
            try:
                await self.encrypting_cycle(id)
                await self.vault.delete(id=id)
            except pe.PangeaAPIException as e:
                print(f"Failed test_asym_encrypting_life_cycle with {algorithm}")
                print(e)
                await self.vault.delete(id=id)
                self.assertTrue(False)

    async def test_asym_signing_life_cycle(self):
        algorithms = [
            AsymmetricAlgorithm.Ed25519,
            AsymmetricAlgorithm.RSA2048_PKCS1V15_SHA256,
        ]
        purpose = KeyPurpose.SIGNING
        for algorithm in algorithms:
            id = await self.asym_generate_default(algorithm=algorithm, purpose=purpose)
            try:
                await self.signing_cycle(id)
                await self.vault.delete(id=id)
            except pe.PangeaAPIException as e:
                print(f"Failed {THIS_FUNCTION_NAME()} with {algorithm}")
                print(e)
                await self.vault.delete(id=id)
                self.assertTrue(False)

    async def test_sym_encrypting_life_cycle(self):
        algorithms = [
            SymmetricAlgorithm.AES128_CBC,
            SymmetricAlgorithm.AES256_CBC,
            SymmetricAlgorithm.AES128_CFB,
            SymmetricAlgorithm.AES256_CFB,
            SymmetricAlgorithm.AES256_GCM,
        ]
        purpose = KeyPurpose.ENCRYPTION
        for algorithm in algorithms:
            id = await self.sym_generate_default(algorithm=algorithm, purpose=purpose)
            try:
                await self.encrypting_cycle(id)
                await self.vault.delete(id=id)
            except pe.PangeaAPIException as e:
                print(f"Failed {THIS_FUNCTION_NAME()} with {algorithm}")
                print(e)
                await self.vault.delete(id=id)
                self.assertTrue(False)

    async def test_secret_life_cycle(self):
        name = name = get_name()
        create_resp = await self.vault.secret_store(secret="hello world", name=name)
        id = create_resp.result.id
        secret_v1 = create_resp.result.secret
        self.assertIsNotNone(id)
        self.assertEqual(1, create_resp.result.version)
        self.assertEqual(ItemType.SECRET, create_resp.result.type)

        rotate_resp = await self.vault.secret_rotate(id=id, secret="new hello world")
        secret_v2 = rotate_resp.result.secret
        self.assertEqual(id, rotate_resp.result.id)
        self.assertEqual(2, rotate_resp.result.version)
        self.assertEqual(ItemType.SECRET, rotate_resp.result.type)
        self.assertNotEqual(secret_v1, secret_v2)

        get_resp = await self.vault.get(id)
        self.assertEqual(0, len(get_resp.result.versions))
        self.assertEqual(2, get_resp.result.current_version.version)
        self.assertEqual(secret_v2, get_resp.result.current_version.secret)
        self.assertEqual(ItemType.SECRET, get_resp.result.type)

        # update
        update_resp = await self.vault.update(id, folder="updated")
        self.assertEqual(id, update_resp.result.id)

        state_change_resp = await self.vault.state_change(id, ItemVersionState.DEACTIVATED, version=2)
        self.assertEqual(id, state_change_resp.result.id)

        # This should fail because secret was deactivated
        get_resp = await self.vault.get(id)
        self.assertEqual(id, get_resp.result.id)
        self.assertEqual(0, len(get_resp.result.versions))
        self.assertEqual(ItemVersionState.DEACTIVATED.value, get_resp.result.current_version.state)

    async def test_jwt_asym_life_cycle(self):
        # Create
        algorithms = [
            AsymmetricAlgorithm.ES256,
            AsymmetricAlgorithm.ES384,
            AsymmetricAlgorithm.ES512,
        ]
        purpose = KeyPurpose.JWT
        for algorithm in algorithms:
            id = await self.asym_generate_default(algorithm=algorithm, purpose=purpose)
            try:
                await self.jwt_asym_signing_cycle(id)
                await self.vault.delete(id=id)
            except pe.PangeaAPIException as e:
                print(f"Failed {THIS_FUNCTION_NAME()} with {algorithm}")
                print(e)
                await self.vault.delete(id=id)
                self.assertTrue(False)

    async def test_jwt_sym_life_cycle(self):
        # Create
        algorithms = [
            SymmetricAlgorithm.HS256,
            SymmetricAlgorithm.HS384,
            SymmetricAlgorithm.HS512,
        ]
        purpose = KeyPurpose.JWT
        for algorithm in algorithms:
            id = await self.sym_generate_default(algorithm=algorithm, purpose=purpose)
            try:
                await self.jwt_sym_signing_cycle(id)
                await self.vault.delete(id=id)
            except pe.PangeaAPIException as e:
                print(f"Failed {THIS_FUNCTION_NAME()} with {algorithm}")
                print(e)
                await self.vault.delete(id=id)
                self.assertTrue(False)

    async def test_list(self):
        list_resp = await self.vault.list()
        self.assertGreater(list_resp.result.count, 0)
        self.assertGreater(len(list_resp.result.items), 0)

        for i in list_resp.result.items:
            try:
                if i.id is not None and i.type != "folder":
                    del_resp = await self.vault.delete(i.id)
                    self.assertEqual(i.id, del_resp.result.id)
            except pe.PangeaAPIException as e:
                print(i)
                print(e)

    async def test_folders(self):
        FOLDER_PARENT = f"test_parent_folder_{TIME}/"
        FOLDER_NAME = "test_folder_name"
        FOLDER_NAME_NEW = "test_folder_name_new"

        # Create parent
        create_parent_resp = await self.vault.folder_create(name=FOLDER_PARENT, folder="/")
        self.assertIsNotNone(create_parent_resp.result.id)

        # Create folder
        create_folder_resp = await self.vault.folder_create(name=FOLDER_NAME, folder=FOLDER_PARENT)
        self.assertIsNotNone(create_folder_resp.result.id)

        # Update name
        update_folder_resp = await self.vault.update(id=create_folder_resp.result.id, name=FOLDER_NAME_NEW)
        self.assertEqual(create_folder_resp.result.id, update_folder_resp.result.id)

        # List
        list_resp = await self.vault.list(filter={"folder": FOLDER_PARENT})
        self.assertEqual(1, list_resp.result.count)
        self.assertEqual(create_folder_resp.result.id, list_resp.result.items[0].id)
        self.assertEqual("folder", list_resp.result.items[0].type)
        self.assertEqual(FOLDER_NAME_NEW, list_resp.result.items[0].name)

        # Delete folder
        delete_resp = await self.vault.delete(id=update_folder_resp.result.id)
        self.assertEqual(delete_resp.result.id, update_folder_resp.result.id)

        # Delete parent folder
        delete_resp = await self.vault.delete(id=create_parent_resp.result.id)
        self.assertEqual(delete_resp.result.id, create_parent_resp.result.id)

    async def test_encrypt_structured(self):
        key = await self.vault.symmetric_generate(
            algorithm=SymmetricAlgorithm.AES256_CFB, purpose=KeyPurpose.ENCRYPTION, name=get_name()
        )
        self.assertIsNotNone(key.result)

        data: dict[str, str | list[bool | str]] = {"field1": [1, 2, "true", "false"], "field2": "data2"}

        encrypted = await self.vault.encrypt_structured(id=key.result.id, structured_data=data, filter="$.field1[2:4]")
        self.assertIsNotNone(encrypted.result)

        encrypted_data = encrypted.result.structured_data
        self.assertIn("field1", encrypted_data)
        self.assertEqual(len(data["field1"]), len(encrypted_data["field1"]))
        self.assertEqual(data["field1"][0], encrypted_data["field1"][0])
        self.assertEqual(data["field1"][1], encrypted_data["field1"][1])
        self.assertNotEqual(data["field1"][2], encrypted_data["field1"][2])
        self.assertNotEqual(data["field1"][3], encrypted_data["field1"][3])

        self.assertIn("field2", encrypted_data)
        self.assertEqual(data["field2"], encrypted_data["field2"])

        decrypted = await self.vault.decrypt_structured(
            id=key.result.id, structured_data=encrypted_data, filter="$.field1[2:4]"
        )
        self.assertIsNotNone(decrypted.result)

        decrypted_data = decrypted.result.structured_data
        self.assertDictEqual(data, decrypted_data)
