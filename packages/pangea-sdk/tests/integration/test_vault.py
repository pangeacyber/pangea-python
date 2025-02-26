from __future__ import annotations

import datetime
import inspect
import json
import random
import unittest
from typing import cast

from typing_extensions import Literal

import pangea.exceptions as pe
from pangea import PangeaConfig
from pangea.crypto import rsa
from pangea.crypto.rsa import kem_decrypt_export_result
from pangea.services.vault.models.asymmetric import (
    AsymmetricKeyAlgorithm,
    AsymmetricKeyEncryptionAlgorithm,
    AsymmetricKeyJwtAlgorithm,
    AsymmetricKeyPurpose,
    AsymmetricKeySigningAlgorithm,
)
from pangea.services.vault.models.common import (
    ExportEncryptionType,
    Metadata,
    RequestManualRotationState,
    RequestRotationState,
    Tags,
)
from pangea.services.vault.models.symmetric import (
    SymmetricKeyAlgorithm,
    SymmetricKeyEncryptionAlgorithm,
    SymmetricKeyFpeAlgorithm,
    SymmetricKeyJwtAlgorithm,
    SymmetricKeyPurpose,
)
from pangea.services.vault.vault import ExportEncryptionAlgorithm, ItemType, ItemVersionState, TransformAlphabet, Vault
from pangea.tools import TestEnvironment, get_test_domain, get_test_token, logger_set_pangea_config
from pangea.utils import format_datetime, str2str_b64, str_b64_2bytes
from tests.test_tools import load_test_environment

TIME = datetime.datetime.now(tz=datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
FOLDER_VALUE = f"/test_key_folder/{TIME}/"
METADATA_VALUE = cast(Metadata, {"test": "True", "field1": "value1", "field2": "value2"})
TAGS_VALUE = cast(Tags, ["test", "symmetric"])
ROTATION_FREQUENCY_VALUE = "1d"
ROTATION_STATE_VALUE = RequestRotationState.DEACTIVATED
EXPIRATION_VALUE = datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(days=1)
EXPIRATION_VALUE_STR = format_datetime(EXPIRATION_VALUE)
MAX_RANDOM = 1000000
ACTOR = "PythonSDKTest"


def get_random_id() -> str:
    return str(random.randrange(1, MAX_RANDOM))


def get_function_name() -> str:
    return inspect.stack()[1][3]


def get_name() -> str:
    caller_name = inspect.stack()[1][3]
    return f"{TIME}_{ACTOR}_{caller_name}_{get_random_id()}"


KEY_ED25519: dict[str, str | AsymmetricKeySigningAlgorithm] = {
    "algorithm": AsymmetricKeySigningAlgorithm.ED25519,
    "private_key": "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIGthqegkjgddRAn0PWN2FeYC6HcCVQf/Ph9sUbeprTBO\n-----END PRIVATE KEY-----\n",
    "public_key": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAPlGrDliJXUbPc2YWEhFxlL2UbBfLHc3ed1f36FrDtTc=\n-----END PUBLIC KEY-----\n",
}

KEY_AES: dict[str, str | SymmetricKeyEncryptionAlgorithm] = {
    "algorithm": SymmetricKeyEncryptionAlgorithm.AES_CFB_128,
    "key": "oILlp2FUPHWiaqFXl4/1ww==",
}


TEST_ENVIRONMENT = load_test_environment(Vault.service_name, TestEnvironment.LIVE)


class TestVault(unittest.TestCase):
    def setUp(self) -> None:
        self.token = get_test_token(TEST_ENVIRONMENT)
        domain = get_test_domain(TEST_ENVIRONMENT)
        self.config = PangeaConfig(domain=domain, custom_user_agent="sdk-test")
        self.vault = Vault(self.token, config=self.config, logger_name="vault")
        logger_set_pangea_config("vault")

    @classmethod
    def tearDownClass(cls) -> None:
        import time

        token = get_test_token(TEST_ENVIRONMENT)
        domain = get_test_domain(TEST_ENVIRONMENT)
        config = PangeaConfig(domain=domain, custom_user_agent="sdk-test")
        vault = Vault(token, config=config, logger_name="vault")

        last = None
        count = 0
        start = time.time()
        list_call_count = 0
        while count < 1000:
            list_resp = vault.list(
                filter={
                    "name__contains": ACTOR,
                },
                last=last,
            )
            list_call_count += 1
            print(f"List call count: {list_call_count}")
            assert list_resp.result

            for i in list_resp.result.items:
                try:
                    if (
                        i.id is not None and i.type != "folder" and i.folder != "/service-tokens/"
                    ):  # Skip service token deletion
                        del_resp = vault.delete(i.id)
                        count += 1
                        assert del_resp.result
                        assert i.id == del_resp.result.id
                except pe.PangeaAPIException as e:
                    print(i)
                    print(e)

            if len(list_resp.result.items) == 0:
                print(f"Deleted {count} items")
                break

            last = list_resp.result.last

        end = time.time()
        print(f"Deleted {count} items in {end - start} seconds")
        print(f"Deleted {count / (end - start)} items per second")

    def encrypting_cycle(
        self, id: str, *, key_type: Literal[ItemType.ASYMMETRIC_KEY, ItemType.SYMMETRIC_KEY] = ItemType.ASYMMETRIC_KEY
    ) -> None:
        msg = "thisisamessagetoencrypt"
        data_b64 = str2str_b64(msg)

        # Encrypt 1
        encrypt1_resp = self.vault.encrypt(id, data_b64)
        assert encrypt1_resp.result

        self.assertEqual(id, encrypt1_resp.result.id)
        self.assertEqual(1, encrypt1_resp.result.version)
        cipher_v1 = encrypt1_resp.result.cipher_text
        self.assertIsNotNone(cipher_v1)

        # Rotate
        rotate_resp = self.vault.rotate_key(id, key_type=key_type, rotation_state=RequestManualRotationState.SUSPENDED)
        assert rotate_resp.result
        assert rotate_resp.result.type == key_type
        self.assertEqual(1, len(rotate_resp.result.item_versions))
        self.assertEqual(2, rotate_resp.result.item_versions[0].version)
        self.assertEqual(id, rotate_resp.result.id)

        # Encrypt 2
        encrypt2_resp = self.vault.encrypt(id, data_b64)
        assert encrypt2_resp.result
        self.assertEqual(id, encrypt2_resp.result.id)
        self.assertEqual(2, encrypt2_resp.result.version)
        cipher_v2 = encrypt2_resp.result.cipher_text
        self.assertIsNotNone(cipher_v2)

        # Decrypt 1
        decrypt1_resp = self.vault.decrypt(id, cipher_v1, version=1)
        assert decrypt1_resp.result
        self.assertEqual(data_b64, decrypt1_resp.result.plain_text)

        # Decrypt 2
        decrypt2_resp = self.vault.decrypt(id, cipher_v2, version=2)
        assert decrypt2_resp.result
        self.assertTrue(data_b64, decrypt2_resp.result.plain_text)

        # Update
        update_resp = self.vault.update(id, folder="updated")
        assert update_resp.result
        self.assertEqual(id, update_resp.result.id)

        # Decrypt default version
        decrypt_default_resp = self.vault.decrypt(id, cipher_v2)
        assert decrypt_default_resp.result
        self.assertEqual(data_b64, decrypt_default_resp.result.plain_text)

        # Decrypt wrong id
        with self.assertRaises(pe.VaultItemNotFound):
            self.vault.decrypt("thisisnotandid", cipher_v2, version=2)

        # Deactivate key
        change_state_resp = self.vault.state_change(id, ItemVersionState.DEACTIVATED, version=1)
        assert change_state_resp.result
        self.assertEqual(id, change_state_resp.result.id)

        # Decrypt after deactivated.
        decrypt1_deactivated_resp = self.vault.decrypt(id, cipher_v1, version=1)
        assert decrypt1_deactivated_resp.result
        self.assertEqual(data_b64, decrypt1_deactivated_resp.result.plain_text)

    def encrypting_cycle_fpe(self, id: str) -> None:
        msg = "thisisamessagetoencrypt"
        tweak = str2str_b64("abcdefg")

        # Encrypt 1
        encrypt1_resp = self.vault.encrypt_transform(
            item_id=id, plain_text=msg, tweak=tweak, alphabet=TransformAlphabet.ALPHANUMERIC
        )
        assert encrypt1_resp.result
        self.assertEqual(id, encrypt1_resp.result.id)
        self.assertEqual(1, encrypt1_resp.result.version)
        cipher_v1 = encrypt1_resp.result.cipher_text
        self.assertIsNotNone(cipher_v1)

        # Rotate
        rotate_resp = self.vault.rotate_key(
            id, key_type=ItemType.SYMMETRIC_KEY, rotation_state=RequestManualRotationState.SUSPENDED
        )
        assert rotate_resp.result
        self.assertEqual(1, len(rotate_resp.result.item_versions))
        self.assertEqual(2, rotate_resp.result.item_versions[0].version)
        self.assertEqual(id, rotate_resp.result.id)

        # Encrypt 2
        encrypt2_resp = self.vault.encrypt_transform(
            item_id=id, plain_text=msg, tweak=tweak, alphabet=TransformAlphabet.ALPHANUMERIC
        )
        assert encrypt2_resp.result
        self.assertEqual(id, encrypt2_resp.result.id)
        self.assertEqual(2, encrypt2_resp.result.version)
        cipher_v2 = encrypt2_resp.result.cipher_text
        self.assertIsNotNone(cipher_v2)

        # Decrypt 1
        decrypt1_resp = self.vault.decrypt_transform(
            item_id=id, cipher_text=cipher_v1, tweak=tweak, alphabet=TransformAlphabet.ALPHANUMERIC, version=1
        )
        assert decrypt1_resp.result
        self.assertEqual(msg, decrypt1_resp.result.plain_text)

        # Decrypt 2
        decrypt2_resp = self.vault.decrypt_transform(
            item_id=id, cipher_text=cipher_v2, tweak=tweak, alphabet=TransformAlphabet.ALPHANUMERIC, version=2
        )
        assert decrypt2_resp.result
        self.assertTrue(msg, decrypt2_resp.result.plain_text)

        # Update
        update_resp = self.vault.update(id, folder="updated")
        assert update_resp.result
        self.assertEqual(id, update_resp.result.id)

        # Decrypt default version
        decrypt_default_resp = self.vault.decrypt_transform(
            item_id=id, cipher_text=cipher_v2, tweak=tweak, alphabet=TransformAlphabet.ALPHANUMERIC
        )
        assert decrypt_default_resp.result
        self.assertEqual(msg, decrypt_default_resp.result.plain_text)

        # Deactivate key
        change_state_resp = self.vault.state_change(id, ItemVersionState.DEACTIVATED, version=1)
        assert change_state_resp.result
        self.assertEqual(id, change_state_resp.result.id)

        # Decrypt after deactivated.
        decrypt1_deactivated_resp = self.vault.decrypt_transform(
            item_id=id, cipher_text=cipher_v1, tweak=tweak, alphabet=TransformAlphabet.ALPHANUMERIC, version=1
        )
        assert decrypt1_deactivated_resp.result
        self.assertEqual(msg, decrypt1_deactivated_resp.result.plain_text)

    def signing_cycle(self, id: str) -> None:
        msg = "thisisamessagetosign"
        data = str2str_b64(msg)
        # Sign 1
        sign1_resp = self.vault.sign(id, data)
        assert sign1_resp.result
        self.assertEqual(id, sign1_resp.result.id)
        self.assertEqual(1, sign1_resp.result.version)
        signature_v1 = sign1_resp.result.signature
        self.assertIsNotNone(signature_v1)

        # Rotate
        rotate_resp = self.vault.rotate_key(
            id, key_type=ItemType.ASYMMETRIC_KEY, rotation_state=RequestManualRotationState.SUSPENDED
        )
        assert rotate_resp.result
        assert rotate_resp.result.type == ItemType.ASYMMETRIC_KEY
        self.assertEqual(1, len(rotate_resp.result.item_versions))
        self.assertEqual(2, rotate_resp.result.item_versions[0].version)
        self.assertEqual(id, rotate_resp.result.id)

        # Sign 2
        sign2_resp = self.vault.sign(id, data)
        assert sign2_resp.result
        self.assertEqual(id, sign2_resp.result.id)
        self.assertEqual(2, sign2_resp.result.version)
        signature_v2 = sign2_resp.result.signature
        self.assertIsNotNone(signature_v2)

        # Verify 1
        verify1_resp = self.vault.verify(id, data, signature_v1, version=1)
        assert verify1_resp.result
        self.assertEqual(id, verify1_resp.result.id)
        self.assertEqual(1, verify1_resp.result.version)
        self.assertTrue(verify1_resp.result.valid_signature)

        # Verify 2
        verify2_resp = self.vault.verify(id, data, signature_v2, version=2)
        assert verify2_resp.result
        self.assertEqual(id, verify2_resp.result.id)
        self.assertEqual(2, verify2_resp.result.version)
        self.assertTrue(verify2_resp.result.valid_signature)

        # Verify default version
        verify_default_resp = self.vault.verify(id, data, signature_v2)
        assert verify_default_resp.result
        self.assertEqual(id, verify_default_resp.result.id)
        self.assertEqual(2, verify_default_resp.result.version)
        self.assertTrue(verify_default_resp.result.valid_signature)

        # Update
        update_resp = self.vault.update(id, folder="updated")
        assert update_resp.result
        self.assertEqual(id, update_resp.result.id)

        # Verify not existing version
        with self.assertRaises(pe.PangeaAPIException):
            self.vault.verify(id, data, signature_v2, version=10)

        # Verify wrong id
        with self.assertRaises(pe.VaultItemNotFound):
            self.vault.verify("thisisnotandid", data, signature_v2, version=2)

        # Verify wrong signature
        with self.assertRaises(pe.PangeaAPIException):
            self.vault.verify(id, data, "thisisnotasignature", version=2)

        # Verify wrong data
        with self.assertRaises(pe.PangeaAPIException):
            self.vault.verify(id, "thisisnotvaliddatax", signature_v2, version=2)

        # Deactivate key
        state_change_resp = self.vault.state_change(id, ItemVersionState.DEACTIVATED, version=1)
        assert state_change_resp.result
        self.assertEqual(id, state_change_resp.result.id)

        # Verify after deactivated.
        verify1_deactivated_resp = self.vault.verify(id, data, signature_v1, version=1)
        assert verify1_deactivated_resp.result
        self.assertEqual(id, verify1_deactivated_resp.result.id)
        self.assertEqual(1, verify1_deactivated_resp.result.version)
        self.assertTrue(verify1_deactivated_resp.result.valid_signature)

    def sym_generate_default(self, algorithm: SymmetricKeyAlgorithm, purpose: SymmetricKeyPurpose) -> str:
        name = get_name()
        response = self.vault.generate_key(
            key_type=ItemType.SYMMETRIC_KEY, algorithm=algorithm, purpose=purpose, name=name
        )
        assert response.result
        self.assertEqual(ItemType.SYMMETRIC_KEY.value, response.result.type)
        self.assertEqual(1, len(response.result.item_versions))
        self.assertIsNotNone(response.result.id)
        self.assertEqual(algorithm.value, response.result.algorithm)
        return response.result.id

    def sym_generate_all_params(self, algorithm: SymmetricKeyAlgorithm, purpose: SymmetricKeyPurpose) -> str:
        name = get_name()
        generated = self.vault.generate_key(
            key_type=ItemType.SYMMETRIC_KEY,
            algorithm=algorithm,
            purpose=purpose,
            name=name,
            folder=FOLDER_VALUE,
            metadata=METADATA_VALUE,
            tags=TAGS_VALUE,
            rotation_frequency=ROTATION_FREQUENCY_VALUE,
            rotation_state=ROTATION_STATE_VALUE,
            disabled_at=EXPIRATION_VALUE,
        )
        assert generated.result
        self.assertEqual(ItemType.SYMMETRIC_KEY.value, generated.result.type)
        self.assertEqual(1, len(generated.result.item_versions))
        self.assertIsNotNone(generated.result.id)

        response = self.vault.get(item_id=generated.result.id)
        assert response.result
        assert response.result.type == ItemType.SYMMETRIC_KEY
        self.assertEqual(1, len(response.result.item_versions))
        self.assertEqual(1, response.result.item_versions[0].version)
        self.assertEqual(name, response.result.name)
        self.assertEqual(FOLDER_VALUE, response.result.folder)
        self.assertEqual(METADATA_VALUE, response.result.metadata)
        self.assertEqual(TAGS_VALUE, response.result.tags)
        self.assertEqual(ROTATION_FREQUENCY_VALUE, response.result.rotation_frequency)
        self.assertEqual(ROTATION_STATE_VALUE.value, response.result.rotation_state)
        self.assertEqual(EXPIRATION_VALUE_STR, response.result.disabled_at)
        return response.result.id

    def test_sym_aes_store_default(self) -> None:
        name = get_name()
        response = self.vault.store_key(
            key_type=ItemType.SYMMETRIC_KEY,
            purpose=SymmetricKeyPurpose.ENCRYPTION,
            name=name,
            algorithm=cast(SymmetricKeyEncryptionAlgorithm, KEY_AES["algorithm"]),
            key=KEY_AES["key"],
        )
        assert response.result
        assert response.result.type == ItemType.SYMMETRIC_KEY
        assert response.result.item_versions[0].version == 1
        assert response.result.id

    def test_sym_aes_store_all_params(self) -> None:
        name = get_name()
        response = self.vault.store_key(
            key_type=ItemType.SYMMETRIC_KEY,
            name=name,
            folder=FOLDER_VALUE,
            metadata=METADATA_VALUE,
            tags=TAGS_VALUE,
            rotation_frequency=ROTATION_FREQUENCY_VALUE,
            rotation_state=ROTATION_STATE_VALUE,
            disabled_at=EXPIRATION_VALUE,
            purpose=SymmetricKeyPurpose.ENCRYPTION,
            algorithm=cast(SymmetricKeyEncryptionAlgorithm, KEY_AES["algorithm"]),
            key=KEY_AES["key"],
        )
        assert response.result
        assert response.result.type == ItemType.SYMMETRIC_KEY
        assert response.result.item_versions[0].version == 1
        assert response.result.id

        response2 = self.vault.get(item_id=response.result.id)
        assert response2.result
        assert response2.result.type == ItemType.SYMMETRIC_KEY
        self.assertEqual(1, len(response2.result.item_versions))
        self.assertEqual(1, response2.result.item_versions[0].version)
        self.assertEqual(name, response2.result.name)
        self.assertEqual(FOLDER_VALUE, response2.result.folder)
        self.assertEqual(METADATA_VALUE, response2.result.metadata)
        self.assertEqual(TAGS_VALUE, response2.result.tags)
        self.assertEqual(ROTATION_FREQUENCY_VALUE, response2.result.rotation_frequency)
        self.assertEqual(ROTATION_STATE_VALUE.value, response2.result.rotation_state)
        self.assertEqual(EXPIRATION_VALUE_STR, response2.result.disabled_at)

    def test_asym_ed25519_store_default(self) -> None:
        name = get_name()
        response = self.vault.store_key(
            key_type=ItemType.ASYMMETRIC_KEY,
            purpose=AsymmetricKeyPurpose.SIGNING,
            name=name,
            algorithm=cast(AsymmetricKeySigningAlgorithm, KEY_ED25519["algorithm"]),
            public_key=KEY_ED25519["public_key"],
            private_key=KEY_ED25519["private_key"],
        )
        assert response.result
        assert response.result.type == ItemType.ASYMMETRIC_KEY
        self.assertEqual(1, response.result.item_versions[0].version)
        self.assertIsNotNone(response.result.id)

    def test_asym_ed25519_store_all_params(self) -> None:
        name = get_name()
        response = self.vault.store_key(
            key_type=ItemType.ASYMMETRIC_KEY,
            name=name,
            folder=FOLDER_VALUE,
            metadata=METADATA_VALUE,
            tags=TAGS_VALUE,
            rotation_frequency=ROTATION_FREQUENCY_VALUE,
            rotation_state=ROTATION_STATE_VALUE,
            disabled_at=EXPIRATION_VALUE,
            purpose=AsymmetricKeyPurpose.SIGNING,
            algorithm=cast(AsymmetricKeySigningAlgorithm, KEY_ED25519["algorithm"]),
            public_key=KEY_ED25519["public_key"],
            private_key=KEY_ED25519["private_key"],
        )
        assert response.result
        assert response.result.type == ItemType.ASYMMETRIC_KEY
        self.assertEqual(1, response.result.item_versions[0].version)
        self.assertIsNotNone(response.result.id)

        response2 = self.vault.get(item_id=response.result.id)
        assert response2.result
        assert response2.result.type == ItemType.ASYMMETRIC_KEY
        self.assertEqual(1, len(response2.result.item_versions))
        self.assertEqual(1, response2.result.item_versions[0].version)
        self.assertEqual(name, response2.result.name)
        self.assertEqual(FOLDER_VALUE, response2.result.folder)
        self.assertEqual(METADATA_VALUE, response2.result.metadata)
        self.assertEqual(TAGS_VALUE, response2.result.tags)
        self.assertEqual(ROTATION_FREQUENCY_VALUE, response2.result.rotation_frequency)
        self.assertEqual(ROTATION_STATE_VALUE.value, response2.result.rotation_state)
        self.assertEqual(EXPIRATION_VALUE_STR, response2.result.disabled_at)

    def asym_generate_default(self, algorithm: AsymmetricKeyAlgorithm, purpose: AsymmetricKeyPurpose) -> str:
        name = get_name()
        response = self.vault.generate_key(
            key_type=ItemType.ASYMMETRIC_KEY, algorithm=algorithm, purpose=purpose, name=name
        )
        assert response.result
        assert response.result.type == ItemType.ASYMMETRIC_KEY
        self.assertEqual(1, response.result.item_versions[0].version)
        self.assertIsNotNone(response.result.id)
        self.assertEqual(algorithm.value, response.result.algorithm)
        return response.result.id

    def asym_generate_all_params(self, algorithm: AsymmetricKeyAlgorithm, purpose: AsymmetricKeyPurpose) -> str:
        name = get_name()
        generated = self.vault.generate_key(
            key_type=ItemType.ASYMMETRIC_KEY,
            algorithm=algorithm,
            purpose=purpose,
            name=name,
            folder=FOLDER_VALUE,
            metadata=METADATA_VALUE,
            tags=TAGS_VALUE,
            rotation_frequency=ROTATION_FREQUENCY_VALUE,
            rotation_state=ROTATION_STATE_VALUE,
            disabled_at=EXPIRATION_VALUE,
        )
        assert generated.result
        self.assertEqual(ItemType.ASYMMETRIC_KEY.value, generated.result.type)
        self.assertEqual(1, len(generated.result.item_versions))
        self.assertIsNotNone(generated.result.id)
        self.assertEqual(algorithm.value, generated.result.algorithm)

        response = self.vault.get(item_id=generated.result.id)
        assert response.result
        assert response.result.type == ItemType.ASYMMETRIC_KEY
        self.assertEqual(1, len(response.result.item_versions))
        self.assertEqual(1, response.result.item_versions[0].version)
        self.assertEqual(name, response.result.name)
        self.assertEqual(FOLDER_VALUE, response.result.folder)
        self.assertEqual(METADATA_VALUE, response.result.metadata)
        self.assertEqual(TAGS_VALUE, response.result.tags)
        self.assertEqual(ROTATION_FREQUENCY_VALUE, response.result.rotation_frequency)
        self.assertEqual(ROTATION_STATE_VALUE.value, response.result.rotation_state)
        self.assertEqual(EXPIRATION_VALUE_STR, response.result.disabled_at)
        return response.result.id

    def jwt_sym_signing_cycle(self, id: str) -> None:
        data = {"message": "message to sign", "data": "Some extra data"}
        payload = json.dumps(data)

        # Sign 1
        sign1_resp = self.vault.jwt_sign(id, payload)
        assert sign1_resp.result
        jws_v1 = sign1_resp.result.jws
        self.assertIsNotNone(jws_v1)

        # Rotate
        rotate_resp = self.vault.rotate_key(
            id, key_type=ItemType.SYMMETRIC_KEY, rotation_state=RequestManualRotationState.SUSPENDED
        )
        assert rotate_resp.result
        self.assertEqual(1, len(rotate_resp.result.item_versions))
        self.assertEqual(2, rotate_resp.result.item_versions[0].version)
        self.assertEqual(id, rotate_resp.result.id)

        # Sign 2
        sign2_resp = self.vault.jwt_sign(id, payload)
        assert sign2_resp.result
        jws_v2 = sign2_resp.result.jws
        self.assertIsNotNone(jws_v2)

        # Verify 1
        verify1_resp = self.vault.jwt_verify(jws_v1)
        assert verify1_resp.result
        self.assertTrue(verify1_resp.result.valid_signature)

        # Verify 2
        verify2_resp = self.vault.jwt_verify(jws_v2)
        assert verify2_resp.result
        self.assertTrue(verify2_resp.result.valid_signature)

        # Update
        update_resp = self.vault.update(id, folder="updated")
        assert update_resp.result
        self.assertEqual(id, update_resp.result.id)

        # Deactivate key
        state_change_resp = self.vault.state_change(id, ItemVersionState.DEACTIVATED, version=1)
        assert state_change_resp.result
        self.assertEqual(id, state_change_resp.result.id)

        # Verify after deactivated.
        verify1_deactivated_resp = self.vault.jwt_verify(jws_v1)
        assert verify1_deactivated_resp.result
        self.assertTrue(verify1_deactivated_resp.result.valid_signature)

    def jwt_asym_signing_cycle(self, id: str) -> None:
        data = {"message": "message to sign", "data": "Some extra data"}
        payload = json.dumps(data)

        # Sign 1
        sign1_resp = self.vault.jwt_sign(id, payload)
        assert sign1_resp.result
        jws_v1 = sign1_resp.result.jws
        self.assertIsNotNone(jws_v1)

        # Rotate
        rotate_resp = self.vault.rotate_key(
            id, key_type=ItemType.ASYMMETRIC_KEY, rotation_state=RequestManualRotationState.SUSPENDED
        )
        assert rotate_resp.result
        self.assertEqual(1, len(rotate_resp.result.item_versions))
        self.assertEqual(2, rotate_resp.result.item_versions[0].version)
        self.assertEqual(id, rotate_resp.result.id)

        # Sign 2
        sign2_resp = self.vault.jwt_sign(id, payload)
        assert sign2_resp.result
        jws_v2 = sign2_resp.result.jws
        self.assertIsNotNone(jws_v2)

        # Verify 1
        verify1_resp = self.vault.jwt_verify(jws_v1)
        assert verify1_resp.result
        self.assertTrue(verify1_resp.result.valid_signature)

        # Verify 2
        verify2_resp = self.vault.jwt_verify(jws_v2)
        assert verify2_resp.result
        self.assertTrue(verify2_resp.result.valid_signature)

        # Update
        update_resp = self.vault.update(id, folder="updated")
        assert update_resp.result
        self.assertEqual(id, update_resp.result.id)

        # Get default
        get_resp = self.vault.jwk_get(id)
        assert get_resp.result
        self.assertEqual(1, len(get_resp.result.keys))

        # Get version 1
        get_resp = self.vault.jwk_get(id, version="1")
        assert get_resp.result
        self.assertEqual(1, len(get_resp.result.keys))

        # Get all
        get_resp = self.vault.jwk_get(id, version="all")
        assert get_resp.result
        self.assertEqual(2, len(get_resp.result.keys))

        # Get version -1
        get_resp = self.vault.jwk_get(id, version="-1")
        assert get_resp.result
        self.assertEqual(1, len(get_resp.result.keys))

        # Deactivate key
        state_change_resp = self.vault.state_change(id, ItemVersionState.DEACTIVATED, version=1)
        assert state_change_resp.result
        self.assertEqual(id, state_change_resp.result.id)

        # Verify after deactivated.
        verify1_deactivated_resp = self.vault.jwt_verify(jws_v1)
        assert verify1_deactivated_resp.result
        self.assertTrue(verify1_deactivated_resp.result.valid_signature)

    def test_generate_asym_signing_all_params(self) -> None:
        algorithms = list(AsymmetricKeySigningAlgorithm)
        purpose = AsymmetricKeyPurpose.SIGNING
        for a in algorithms:
            print(f"Test {get_function_name()}. Generate {a} {purpose}...")
            item_id = self.asym_generate_all_params(algorithm=a, purpose=purpose)
            self.vault.delete(item_id=item_id)

    def test_generate_asym_encrypting_all_params(self) -> None:
        algorithms = list(AsymmetricKeyEncryptionAlgorithm)
        purpose = AsymmetricKeyPurpose.ENCRYPTION
        for a in algorithms:
            print(f"Test {get_function_name()}. Generate {a} {purpose}...")
            item_id = self.asym_generate_all_params(algorithm=a, purpose=purpose)
            self.vault.delete(item_id=item_id)

    def test_generate_sym_encrypting_all_params(self) -> None:
        algorithms = list(SymmetricKeyEncryptionAlgorithm)
        purpose = SymmetricKeyPurpose.ENCRYPTION
        for a in algorithms:
            print(f"Test {get_function_name()}. Generate {a} {purpose}...")
            item_id = self.sym_generate_all_params(algorithm=a, purpose=purpose)
            self.vault.delete(item_id=item_id)

    def test_asym_encrypting_life_cycle(self) -> None:
        algorithms = [AsymmetricKeyEncryptionAlgorithm.RSA_OAEP_2048_SHA256]
        purpose = AsymmetricKeyPurpose.ENCRYPTION
        for algorithm in algorithms:
            item_id = self.asym_generate_default(algorithm=algorithm, purpose=purpose)
            try:
                self.encrypting_cycle(item_id)
            except pe.PangeaAPIException:
                print(f"Failed {get_function_name()} with {algorithm}")
                raise
            finally:
                self.vault.delete(item_id=item_id)

    def test_asym_signing_life_cycle(self) -> None:
        algorithms = [AsymmetricKeySigningAlgorithm.ED25519, AsymmetricKeySigningAlgorithm.RSA_PKCS1V15_2048_SHA256]
        purpose = AsymmetricKeyPurpose.SIGNING
        for algorithm in algorithms:
            item_id = self.asym_generate_default(algorithm=algorithm, purpose=purpose)
            try:
                self.signing_cycle(item_id)
            except pe.PangeaAPIException:
                print(f"Failed {get_function_name()} with {algorithm}")
                raise
            finally:
                self.vault.delete(item_id=item_id)

    def test_sym_encrypting_life_cycle(self) -> None:
        algorithms = list(SymmetricKeyEncryptionAlgorithm)
        purpose = SymmetricKeyPurpose.ENCRYPTION
        for algorithm in algorithms:
            item_id = self.sym_generate_default(algorithm=algorithm, purpose=purpose)
            try:
                self.encrypting_cycle(item_id, key_type=ItemType.SYMMETRIC_KEY)
            except pe.PangeaAPIException:
                print(f"Failed {get_function_name()} with {algorithm}")
                raise
            finally:
                self.vault.delete(item_id=item_id)

    def test_sym_fpe_encrypting_life_cycle(self) -> None:
        algorithms = list(SymmetricKeyFpeAlgorithm)
        purpose = SymmetricKeyPurpose.FPE
        for algorithm in algorithms:
            key_id = self.sym_generate_default(algorithm=algorithm, purpose=purpose)
            try:
                self.encrypting_cycle_fpe(key_id)
                self.vault.delete(item_id=key_id)
            except pe.PangeaAPIException as e:
                print(f"Failed {get_function_name()} with {algorithm}")
                print(e)
                self.vault.delete(item_id=key_id)
                self.fail()

    def test_secret_life_cycle(self) -> None:
        name = get_name()
        create_resp = self.vault.store_secret(secret="hello world", name=name)
        assert create_resp.result
        id = create_resp.result.id
        self.assertIsNotNone(id)
        self.assertEqual(ItemType.SECRET, create_resp.result.type)

        rotate_resp = self.vault.rotate_secret(id, secret="new hello world")
        assert rotate_resp.result
        self.assertEqual(id, rotate_resp.result.id)
        self.assertEqual(ItemType.SECRET, rotate_resp.result.type)

        get_resp = self.vault.get(id)
        assert get_resp.result
        assert get_resp.result.type == ItemType.SECRET
        self.assertEqual(1, len(get_resp.result.item_versions))
        self.assertEqual(2, get_resp.result.item_versions[0].version)

        # update
        update_resp = self.vault.update(id, folder="updated")
        assert update_resp.result
        self.assertEqual(id, update_resp.result.id)

        state_change_resp = self.vault.state_change(id, ItemVersionState.DEACTIVATED, version=2)
        assert state_change_resp.result
        self.assertEqual(id, state_change_resp.result.id)

        # This should fail because secret was deactivated
        get_resp = self.vault.get(id)
        assert get_resp.result
        assert get_resp.result.type == ItemType.SECRET
        self.assertEqual(id, get_resp.result.id)
        self.assertEqual(1, len(get_resp.result.item_versions))
        self.assertEqual(ItemVersionState.DEACTIVATED, get_resp.result.item_versions[0].state)

    def test_jwt_asym_life_cycle(self) -> None:
        algorithms = list(AsymmetricKeyJwtAlgorithm)
        purpose = AsymmetricKeyPurpose.JWT
        for algorithm in algorithms:
            key_id = self.asym_generate_default(algorithm=algorithm, purpose=purpose)
            try:
                self.jwt_asym_signing_cycle(key_id)
            except pe.PangeaAPIException:
                print(f"Failed {get_function_name()} with {algorithm}")
                raise
            finally:
                self.vault.delete(item_id=key_id)

    def test_jwt_sym_life_cycle(self) -> None:
        # Create
        algorithms = list(SymmetricKeyJwtAlgorithm)
        purpose = SymmetricKeyPurpose.JWT
        for algorithm in algorithms:
            key_id = self.sym_generate_default(algorithm=algorithm, purpose=purpose)
            try:
                self.jwt_sym_signing_cycle(key_id)
            except pe.PangeaAPIException:
                print(f"Failed {get_function_name()} with {algorithm}")
                raise
            finally:
                self.vault.delete(item_id=key_id)

    def test_folders(self) -> None:
        FOLDER_PARENT = f"test_parent_folder_{TIME}/"
        FOLDER_NAME = "test_folder_name"
        FOLDER_NAME_NEW = "test_folder_name_new"

        # Create parent
        create_parent_resp = self.vault.folder_create(name=FOLDER_PARENT, folder="/")
        assert create_parent_resp.result
        self.assertIsNotNone(create_parent_resp.result.id)

        # Create folder
        create_folder_resp = self.vault.folder_create(name=FOLDER_NAME, folder=FOLDER_PARENT)
        assert create_folder_resp.result
        self.assertIsNotNone(create_folder_resp.result.id)

        # Update name
        update_folder_resp = self.vault.update(item_id=create_folder_resp.result.id, name=FOLDER_NAME_NEW)
        assert update_folder_resp.result
        self.assertEqual(create_folder_resp.result.id, update_folder_resp.result.id)

        # List
        list_resp = self.vault.list(filter={"folder": FOLDER_PARENT})
        assert list_resp.result
        self.assertEqual(1, len(list_resp.result.items))
        self.assertEqual(create_folder_resp.result.id, list_resp.result.items[0].id)
        self.assertEqual("folder", list_resp.result.items[0].type)
        self.assertEqual(FOLDER_NAME_NEW, list_resp.result.items[0].name)

        # Delete folder
        delete_resp = self.vault.delete(item_id=update_folder_resp.result.id)
        assert delete_resp.result
        self.assertEqual(delete_resp.result.id, update_folder_resp.result.id)

        # Delete parent folder
        delete_resp = self.vault.delete(item_id=create_parent_resp.result.id)
        assert delete_resp.result
        self.assertEqual(delete_resp.result.id, create_parent_resp.result.id)

    def test_encrypt_structured(self) -> None:
        key = self.vault.generate_key(
            key_type=ItemType.SYMMETRIC_KEY,
            purpose=SymmetricKeyPurpose.ENCRYPTION,
            algorithm=SymmetricKeyEncryptionAlgorithm.AES_CFB_256,
            name=get_name(),
        )
        assert key.result

        data: dict[str, str | list[int | str]] = {"field1": [1, 2, "true", "false"], "field2": "data2"}

        encrypted = self.vault.encrypt_structured(
            key_id=key.result.id, structured_data=data, filter_expr="$.field1[2:4]"
        )
        assert encrypted.result

        encrypted_data = encrypted.result.structured_data
        self.assertIn("field1", encrypted_data)
        self.assertEqual(len(data["field1"]), len(encrypted_data["field1"]))
        self.assertEqual(data["field1"][0], encrypted_data["field1"][0])
        self.assertEqual(data["field1"][1], encrypted_data["field1"][1])
        self.assertNotEqual(data["field1"][2], encrypted_data["field1"][2])
        self.assertNotEqual(data["field1"][3], encrypted_data["field1"][3])

        self.assertIn("field2", encrypted_data)
        self.assertEqual(data["field2"], encrypted_data["field2"])

        decrypted = self.vault.decrypt_structured(
            key_id=key.result.id, structured_data=encrypted_data, filter_expr="$.field1[2:4]"
        )
        assert decrypted.result

        decrypted_data = decrypted.result.structured_data
        self.assertDictEqual(data, decrypted_data)

    def test_export_generate_asymmetric(self) -> None:
        name = get_name()
        algorithm = AsymmetricKeySigningAlgorithm.ED25519
        purpose = AsymmetricKeyPurpose.SIGNING
        response = self.vault.generate_key(
            key_type=ItemType.ASYMMETRIC_KEY, algorithm=algorithm, purpose=purpose, name=name, exportable=True
        )
        assert response.result
        key_id = response.result.id
        self.assertIsNotNone(key_id)
        self.assertEqual(ItemType.ASYMMETRIC_KEY.value, response.result.type)

        # export no encryption
        exp_resp = self.vault.export(item_id=key_id)
        assert exp_resp.result
        self.assertEqual(key_id, exp_resp.result.id)
        self.assertEqual(1, exp_resp.result.version)
        self.assertEqual(ItemType.ASYMMETRIC_KEY, exp_resp.result.type)
        self.assertEqual(ExportEncryptionType.NONE, exp_resp.result.encryption_type)
        assert exp_resp.result.public_key
        assert exp_resp.result.private_key

        # generate key pair
        rsa_priv_key, rsa_pub_key = rsa.generate_key_pair()
        rsa_pub_key_pem = rsa.public_key_to_pem(rsa_pub_key)

        # export with encryption
        exp_encrypted_resp = self.vault.export(
            item_id=key_id,
            asymmetric_public_key=rsa_pub_key_pem.decode("utf-8"),
            asymmetric_algorithm=ExportEncryptionAlgorithm.RSA4096_OAEP_SHA512,
        )
        assert exp_encrypted_resp.result
        self.assertEqual(key_id, exp_encrypted_resp.result.id)
        self.assertEqual(1, exp_encrypted_resp.result.version)
        self.assertEqual(ItemType.ASYMMETRIC_KEY, exp_encrypted_resp.result.type)
        self.assertEqual(ExportEncryptionType.ASYMMETRIC, exp_encrypted_resp.result.encryption_type)
        assert exp_encrypted_resp.result.private_key

        # Decrypt key
        exp_priv_key_decoded = str_b64_2bytes(exp_encrypted_resp.result.private_key)
        exp_priv_key_pem = rsa.decrypt_sha512(rsa_priv_key, exp_priv_key_decoded)

        self.assertEqual(exp_priv_key_pem, exp_resp.result.private_key.encode("utf-8"))
        self.assertEqual(exp_encrypted_resp.result.public_key, exp_resp.result.public_key)

    def test_export_generate_symmetric(self) -> None:
        name = get_name()
        algorithm = SymmetricKeyEncryptionAlgorithm.AES_CBC_128
        purpose = SymmetricKeyPurpose.ENCRYPTION
        response = self.vault.generate_key(
            key_type=ItemType.SYMMETRIC_KEY, algorithm=algorithm, purpose=purpose, name=name, exportable=True
        )
        assert response.result
        key_id = response.result.id
        self.assertIsNotNone(key_id)
        self.assertEqual(ItemType.SYMMETRIC_KEY, response.result.type)

        # export no encryption
        exp_resp = self.vault.export(item_id=key_id)
        assert exp_resp.result
        self.assertEqual(key_id, exp_resp.result.id)
        self.assertEqual(1, exp_resp.result.version)
        self.assertEqual(ItemType.SYMMETRIC_KEY, exp_resp.result.type)
        self.assertEqual(ExportEncryptionType.NONE, exp_resp.result.encryption_type)
        self.assertIsNone(exp_resp.result.public_key)
        self.assertIsNone(exp_resp.result.private_key)
        assert exp_resp.result.key

        # generate key pair
        rsa_priv_key, rsa_pub_key = rsa.generate_key_pair()
        rsa_pub_key_pem = rsa.public_key_to_pem(rsa_pub_key)

        # export with encryption
        exp_encrypted_resp = self.vault.export(
            item_id=key_id,
            version=1,
            asymmetric_public_key=rsa_pub_key_pem.decode("utf-8"),
            asymmetric_algorithm=ExportEncryptionAlgorithm.RSA4096_OAEP_SHA512,
        )
        assert exp_encrypted_resp.result
        self.assertEqual(key_id, exp_encrypted_resp.result.id)
        self.assertEqual(1, exp_encrypted_resp.result.version)
        self.assertEqual(ItemType.SYMMETRIC_KEY, exp_encrypted_resp.result.type)
        self.assertEqual(ExportEncryptionType.ASYMMETRIC, exp_encrypted_resp.result.encryption_type)
        assert exp_encrypted_resp.result.key

        # Decrypt key
        exp_key_decoded = str_b64_2bytes(exp_encrypted_resp.result.key)
        exp_key_pem = rsa.decrypt_sha512(rsa_priv_key, exp_key_decoded)

        self.assertEqual(exp_key_pem, exp_resp.result.key.encode("utf-8"))

    def test_export_store_asymmetric(self) -> None:
        name = get_name()
        purpose = AsymmetricKeyPurpose.SIGNING
        response = self.vault.store_key(  # type: ignore[call-overload]
            key_type=ItemType.ASYMMETRIC_KEY,
            name=name,
            purpose=purpose,
            exportable=True,
            **KEY_ED25519,
        )
        assert response.result
        key_id = response.result.id
        self.assertIsNotNone(key_id)
        self.assertEqual(ItemType.ASYMMETRIC_KEY.value, response.result.type)

        # export no encryption
        exp_resp = self.vault.export(item_id=key_id)
        assert exp_resp.result
        self.assertEqual(key_id, exp_resp.result.id)
        self.assertEqual(1, exp_resp.result.version)
        self.assertEqual(ItemType.ASYMMETRIC_KEY, exp_resp.result.type)
        self.assertEqual(ExportEncryptionType.NONE, exp_resp.result.encryption_type)
        assert exp_resp.result.public_key
        assert exp_resp.result.private_key

        # generate key pair
        rsa_priv_key, rsa_pub_key = rsa.generate_key_pair()
        rsa_pub_key_pem = rsa.public_key_to_pem(rsa_pub_key)

        # export with encryption
        exp_encrypted_resp = self.vault.export(
            item_id=key_id,
            asymmetric_public_key=rsa_pub_key_pem.decode("utf-8"),
            asymmetric_algorithm=ExportEncryptionAlgorithm.RSA4096_OAEP_SHA512,
        )
        assert exp_encrypted_resp.result
        self.assertEqual(key_id, exp_encrypted_resp.result.id)
        self.assertEqual(1, exp_encrypted_resp.result.version)
        self.assertEqual(ItemType.ASYMMETRIC_KEY, exp_encrypted_resp.result.type)
        self.assertEqual(ExportEncryptionType.ASYMMETRIC, exp_encrypted_resp.result.encryption_type)
        assert exp_encrypted_resp.result.public_key
        assert exp_encrypted_resp.result.private_key

        # Decrypt key
        exp_priv_key_decoded = str_b64_2bytes(exp_encrypted_resp.result.private_key)
        exp_priv_key_pem = rsa.decrypt_sha512(rsa_priv_key, exp_priv_key_decoded)

        self.assertEqual(exp_priv_key_pem, exp_resp.result.private_key.encode("utf-8"))
        self.assertEqual(exp_resp.result.public_key, exp_encrypted_resp.result.public_key)

    def test_export_store_symmetric(self) -> None:
        name = get_name()
        response = self.vault.store_key(  # type: ignore[call-overload]
            **KEY_AES,
            key_type=ItemType.SYMMETRIC_KEY,
            purpose=SymmetricKeyPurpose.ENCRYPTION,
            name=name,
            exportable=True,
        )
        assert response.result
        key_id = response.result.id
        self.assertIsNotNone(key_id)
        self.assertEqual(ItemType.SYMMETRIC_KEY.value, response.result.type)

        # export no encryption
        exp_resp = self.vault.export(item_id=key_id, version=1)
        assert exp_resp.result
        self.assertEqual(key_id, exp_resp.result.id)
        self.assertEqual(1, exp_resp.result.version)
        self.assertEqual(ItemType.SYMMETRIC_KEY, exp_resp.result.type)
        self.assertEqual(ExportEncryptionType.NONE, exp_resp.result.encryption_type)
        assert exp_resp.result.key

        # generate key pair
        rsa_priv_key, rsa_pub_key = rsa.generate_key_pair()
        rsa_pub_key_pem = rsa.public_key_to_pem(rsa_pub_key)

        # export with encryption
        exp_encrypted_resp = self.vault.export(
            item_id=key_id,
            asymmetric_public_key=rsa_pub_key_pem.decode("utf-8"),
            asymmetric_algorithm=ExportEncryptionAlgorithm.RSA4096_OAEP_SHA512,
        )
        assert exp_encrypted_resp.result
        self.assertEqual(key_id, exp_encrypted_resp.result.id)
        self.assertEqual(1, exp_encrypted_resp.result.version)
        self.assertEqual(ItemType.SYMMETRIC_KEY, exp_encrypted_resp.result.type)
        self.assertEqual(ExportEncryptionType.ASYMMETRIC, exp_encrypted_resp.result.encryption_type)
        assert exp_encrypted_resp.result.key

        # Decrypt key
        exp_key_decoded = str_b64_2bytes(exp_encrypted_resp.result.key)
        exp_key_pem = rsa.decrypt_sha512(rsa_priv_key, exp_key_decoded)

        self.assertEqual(exp_key_pem, exp_resp.result.key.encode("utf-8"))

    def test_export_kem(self) -> None:
        # Generate a key pair.
        rsa_priv_key, rsa_pub_key = rsa.generate_key_pair()
        rsa_pub_key_pem = rsa.public_key_to_pem(rsa_pub_key)

        # Generate an exportable key.
        generate_response = self.vault.generate_key(
            key_type=ItemType.ASYMMETRIC_KEY,
            algorithm=AsymmetricKeySigningAlgorithm.ED25519,
            purpose=AsymmetricKeyPurpose.SIGNING,
            name=get_name(),
            exportable=True,
        )
        assert generate_response.result
        key_id = generate_response.result.id
        assert generate_response.result.type == ItemType.ASYMMETRIC_KEY

        # Export without any encryption.
        plain_export = self.vault.export(item_id=key_id)
        assert plain_export.result
        assert plain_export.result.id == key_id
        assert plain_export.result.type == ItemType.ASYMMETRIC_KEY
        assert plain_export.result.private_key

        # Export with KEM.
        kem_export = self.vault.export(
            item_id=key_id,
            asymmetric_algorithm=ExportEncryptionAlgorithm.RSA_NO_PADDING_4096_KEM,
            asymmetric_public_key=rsa_pub_key_pem.decode("utf-8"),
            kem_password="password",
        )
        assert kem_export.result
        assert kem_export.result.id == key_id
        assert kem_export.result.type == ItemType.ASYMMETRIC_KEY
        assert kem_export.result.public_key == plain_export.result.public_key
        assert kem_export.result.encryption_type == ExportEncryptionType.KEM

        kem_decrypt = kem_decrypt_export_result(
            result=kem_export.result,
            password="password",
            private_key=rsa_priv_key,
        )
        assert kem_decrypt == plain_export.result.private_key
