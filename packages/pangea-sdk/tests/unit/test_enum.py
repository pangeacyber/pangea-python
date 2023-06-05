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


class TestConfig(unittest.TestCase):
    def test_audit_enums(self):
        event_verification = EventVerification.PASS
        repr(event_verification)
        print(event_verification)

        event_signing = EventSigning.NONE
        repr(event_signing)
        print(event_signing)

        order = SearchOrder.ASC
        repr(order)
        print(order)

        order_by = SearchOrderBy.MESSAGE
        repr(order_by)
        print(order_by)

    def test_intel_enums(self):
        hash_type = HashType.SHA256
        hash_type
        print(hash_type)

    def test_vault_enums(self):
        kp = KeyPurpose.ENCRYPTION
        repr(kp)
        print(kp)

        aa = AsymmetricAlgorithm.Ed25519
        repr(aa)
        print(aa)

        sa = SymmetricAlgorithm.AES
        repr(sa)
        print(sa)

        io = ItemOrder.ASC
        repr(io)
        print(io)

        iob = ItemOrderBy.CREATED_AT
        repr(iob)
        print(iob)

        it = ItemType.ASYMMETRIC_KEY
        repr(it)
        print(it)

        ivs = ItemVersionState.ACTIVE
        repr(ivs)
        print(ivs)

        item_state = ItemState.DISABLED
        repr(item_state)
        print(item_state)

    def test_tools_enum(self):
        te = TestEnvironment.DEVELOP
        repr(te)
        print(te)
