import unittest

from pangea.services.audit.models import EventSigning, EventVerification, SearchOrder, SearchOrderBy
from pangea.services.intel import HashType
from pangea.services.vault.models.common import (
    AsymmetricAlgorithm,
    ItemOrder,
    ItemOrderBy,
    ItemState,
    ItemType,
    ItemVersionState,
    KeyPurpose,
    SymmetricAlgorithm,
)
from pangea.tools import TestEnvironment


class TestEnums(unittest.TestCase):
    def test_audit_enums(self):
        event_verification = EventVerification.PASS
        repr(event_verification)
        self.assertEqual(str(event_verification), "pass")

        event_signing = EventSigning.NONE
        repr(event_signing)
        self.assertEqual(event_signing.value, 0)

        order = SearchOrder.ASC
        repr(order)
        self.assertEqual(str(order), "asc")

        order_by = SearchOrderBy.MESSAGE
        repr(order_by)
        self.assertEqual(str(order_by), "message")

    def test_intel_enums(self):
        hash_type = HashType.SHA256
        hash_type
        self.assertEqual(str(hash_type), "sha256")

    def test_vault_enums(self):
        kp = KeyPurpose.ENCRYPTION
        repr(kp)
        self.assertEqual(str(kp), "encryption")

        aa = AsymmetricAlgorithm.Ed25519
        repr(aa)
        self.assertEqual(str(aa), "ED25519")

        sa = SymmetricAlgorithm.AES
        repr(sa)
        self.assertEqual(str(sa), "AES-CFB-128")

        io = ItemOrder.ASC
        repr(io)
        self.assertEqual(str(io), "asc")

        iob = ItemOrderBy.CREATED_AT
        repr(iob)
        self.assertEqual(str(iob), "created_at")

        it = ItemType.ASYMMETRIC_KEY
        repr(it)
        self.assertEqual(str(it), "asymmetric_key")

        ivs = ItemVersionState.ACTIVE
        repr(ivs)
        self.assertEqual(str(ivs), "active")

        item_state = ItemState.DISABLED
        repr(item_state)
        self.assertEqual(str(item_state), "disabled")

    def test_tools_enums(self):
        te = TestEnvironment.DEVELOP
        repr(te)
        self.assertEqual(str(te), "DEV")
