import unittest

from pangea.services.audit.models import EventVerification, SearchOrder, SearchOrderBy
from pangea.services.intel import HashType
from pangea.services.vault.models.asymmetric import AsymmetricKeyPurpose, AsymmetricKeySigningAlgorithm
from pangea.services.vault.models.common import ItemOrder, ItemOrderBy, ItemState, ItemType, ItemVersionState
from pangea.services.vault.models.symmetric import SymmetricKeyEncryptionAlgorithm
from pangea.tools import TestEnvironment


class TestEnums(unittest.TestCase):
    def test_audit_enums(self):
        event_verification = EventVerification.PASS
        repr(event_verification)
        self.assertEqual(str(event_verification), "pass")

        order = SearchOrder.ASC
        repr(order)
        self.assertEqual(str(order), "asc")

        order_by = SearchOrderBy.MESSAGE
        repr(order_by)
        self.assertEqual(str(order_by), "message")

    def test_intel_enums(self):
        hash_type = HashType.SHA256
        repr(hash_type)
        self.assertEqual(str(hash_type), "sha256")

    def test_vault_enums(self) -> None:
        kp = AsymmetricKeyPurpose.ENCRYPTION
        self.assertEqual(kp, "encryption")

        aa = AsymmetricKeySigningAlgorithm.ED25519
        self.assertEqual(aa, "ED25519")

        sa = SymmetricKeyEncryptionAlgorithm.AES_CFB_128
        self.assertEqual(sa, "AES-CFB-128")

        io = ItemOrder.ASC
        self.assertEqual(io, "asc")

        iob = ItemOrderBy.CREATED_AT
        self.assertEqual(iob, "created_at")

        it = ItemType.ASYMMETRIC_KEY
        self.assertEqual(it, "asymmetric_key")

        ivs = ItemVersionState.ACTIVE
        self.assertEqual(ivs, "active")

        item_state = ItemState.DISABLED
        self.assertEqual(item_state, "disabled")

    def test_tools_enums(self):
        te = TestEnvironment.DEVELOP
        repr(te)
        self.assertEqual(str(te), "DEV")
