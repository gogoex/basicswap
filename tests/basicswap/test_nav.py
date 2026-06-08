#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (c) 2025 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import unittest

from coincurve.keys import PrivateKey

from basicswap.basicswap_util import MessageTypes, TxLockTypes
from basicswap.interface.nav import NAVInterface
import basicswap.protocols.atomic_swap_1 as atomic_swap_1
from tests.basicswap.util import REQUIRED_SETTINGS

def ci_nav():
    settings = {"rpcport": 0, "rpcauth": "none"}
    settings.update(REQUIRED_SETTINGS)
    return NAVInterface(settings, "regtest")

class TestFakeHTLCScript(unittest.TestCase):
    """Tests for createFakeNonNavHTLCScript and extractHTLCLockVal."""
    def setUp(self):
        self.ci = ci_nav()
        self.secret_hash = bytes(32)

    def test_roundtrip_block_heights(self):
        for lock_value in (1, 100, 123456, 499_999_999):
            script = self.ci.createFakeNonNavHTLCScript(self.secret_hash, lock_value)
            assert self.ci.extractHTLCLockVal(bytes(script), is_nav=False) == lock_value, lock_value

    def test_roundtrip_timestamps(self):
        for lock_value in (500_000_000, 1_700_000_000, 1_800_000_000):
            script = self.ci.createFakeNonNavHTLCScript(self.secret_hash, lock_value)
            assert self.ci.extractHTLCLockVal(bytes(script), is_nav=False) == lock_value, lock_value

    def test_secret_hash_preserved(self):
        secret_hash = bytes(range(32))
        script = self.ci.createFakeNonNavHTLCScript(secret_hash, 123456)
        extracted = atomic_swap_1.extractScriptSecretHash(bytes(script))
        assert extracted == secret_hash

    def test_short_secret_hash_padded(self):
        # extractScriptSecretHash must still recover correct hash after rjust padding
        secret_hash = b'\x01' * 20
        script = self.ci.createFakeNonNavHTLCScript(secret_hash, 100)
        extracted = atomic_swap_1.extractScriptSecretHash(bytes(script))
        assert extracted == secret_hash.rjust(32, b'\x00')

class TestIsHTLCScript(unittest.TestCase):
    """Tests for _isHTLCScript."""
    def setUp(self):
        self.ci = ci_nav()

    def test_valid_script_1_byte_locktime(self):
        # From docstring: 1-byte locktime
        hex1 = (
            "6382012088a820b812e53d1bd15a928803df44ab86c6a286d9a3d6625a3738f"
            "bed32d89a4c7c178830a7b9a59a0e305eef4f756909e6fa107091fc6d2b2743"
            "3d110d5d3c95ff987a0182bbd2e19897ee71af0466006cc2755467042c688b6"
            "9b17530a7b9a59a0e305eef4f756909e6fa107091fc6d2b27433d110d5d3c95"
            "ff987a0182bbd2e19897ee71af0466006cc2755468b3"
        )
        assert self.ci._isHTLCScript(hex1) is True

    def test_valid_script_4_byte_locktime(self):
        # From docstring: 4-byte locktime
        hex2 = (
            "6382012088a8206756e66c48945a6851790e94fed56b86ec9d1e05116d4d289bf"
            "62f858389c3998830a6c43cded614e403d715cd7f28a57736214937dd811bd7e2927eed4cd"
            "904ee8df0066923c7dc021a36e94fa6f8fa21e36703710040b17530a769dfbee940c4f72c1"
            "29b5a315822dabda7932f5f12b8d1c56d2335544995504af3e11446a3b544cb6ec51403377"
            "33468b3"
        )
        assert self.ci._isHTLCScript(hex2) is True

    def test_invalid_p2pkh(self):
        assert self.ci._isHTLCScript("76a91488ac") is False

    def test_invalid_empty(self):
        assert self.ci._isHTLCScript("") is False

    def test_invalid_zeroes(self):
        assert self.ci._isHTLCScript("00" * 100) is False

    def test_case_insensitive(self):
        hex1 = (
            "6382012088a820b812e53d1bd15a928803df44ab86c6a286d9a3d6625a3738f"
            "bed32d89a4c7c178830a7b9a59a0e305eef4f756909e6fa107091fc6d2b2743"
            "3d110d5d3c95ff987a0182bbd2e19897ee71af0466006cc2755467042c688b6"
            "9b17530a7b9a59a0e305eef4f756909e6fa107091fc6d2b27433d110d5d3c95"
            "ff987a0182bbd2e19897ee71af0466006cc2755468b3"
        )
        assert self.ci._isHTLCScript(hex1.upper()) is True

class TestDeriveBlindingKey(unittest.TestCase):
    """Tests for deriveBlindingKey."""
    def setUp(self):
        self.ci = ci_nav()
        self.privA = bytes.fromhex("e6b8e7c2ca3a88fe4f28591aa0f91fec340179346559e4ec430c2531aecc19aa")
        self.privB = bytes.fromhex("b725b6359bd2b510d9d5a7bba7bdee17abbf113253f6338ea50a8f0cf45fd0d0")
        self.pubA = PrivateKey(self.privA).public_key.format(compressed=True)
        self.pubB = PrivateKey(self.privB).public_key.format(compressed=True)

    def test_returns_nonzero_int(self):
        key = self.ci.deriveBlindingKey(self.privA, self.pubB)
        assert isinstance(key, int)
        assert key > 0

    def test_ecdh_commutative(self):
        # ECDH(privA, pubB) == ECDH(privB, pubA) — same shared secret
        key_ab = self.ci.deriveBlindingKey(self.privA, self.pubB)
        key_ba = self.ci.deriveBlindingKey(self.privB, self.pubA)
        assert key_ab == key_ba

    def test_different_keys_different_result(self):
        privC = bytes.fromhex("0b4c6e34c21b910f92c7985a8093de526f5f8677a112a8c672d1098139b70e0f")
        pubC = PrivateKey(privC).public_key.format(compressed=True)
        key_ab = self.ci.deriveBlindingKey(self.privA, self.pubB)
        key_ac = self.ci.deriveBlindingKey(self.privA, pubC)
        assert key_ab != key_ac

    def test_deterministic(self):
        key1 = self.ci.deriveBlindingKey(self.privA, self.pubB)
        key2 = self.ci.deriveBlindingKey(self.privA, self.pubB)
        assert key1 == key2

class TestIsTxNonFinalError(unittest.TestCase):
    """Tests for isTxNonFinalError."""
    def setUp(self):
        self.ci = ci_nav()

    def test_non_final_input(self):
        assert self.ci.isTxNonFinalError("non-final-input") is True
        assert self.ci.isTxNonFinalError("sendrawtransaction: non-final-input (code 64)") is True

    def test_bad_input_unknown(self):
        assert self.ci.isTxNonFinalError("bad-input-unknown") is True
        assert self.ci.isTxNonFinalError("bad-inputs-unknown") is True

    def test_code_25(self):
        assert self.ci.isTxNonFinalError("{'code': 25, 'message': 'Missing inputs'}") is True

    def test_unrelated_errors(self):
        assert self.ci.isTxNonFinalError("insufficient fee") is False
        assert self.ci.isTxNonFinalError("") is False
        assert self.ci.isTxNonFinalError("transaction already in mempool") is False

class TestGetHTLCSpendTxVSize(unittest.TestCase):
    def test_returns_expected_size(self):
        ci = ci_nav()
        assert ci.getHTLCSpendTxVSize(redeem=True) == 1336
        assert ci.getHTLCSpendTxVSize(redeem=False) == 1336

class TestGetSeedHash(unittest.TestCase):
    def test_returns_seed_unchanged(self):
        ci = ci_nav()
        seed = bytes(range(32))
        assert ci.getSeedHash(seed) == seed

class TestTimelockOpcode(unittest.TestCase):
    """Verify timelock_opcode derivation for all 4 lock types."""

    def _opcode(self, lock_type):
        return "csv" if lock_type < TxLockTypes.ABS_LOCK_BLOCKS else "cltv"

    def test_sequence_lock_blocks_gives_csv(self):
        assert self._opcode(TxLockTypes.SEQUENCE_LOCK_BLOCKS) == "csv"

    def test_sequence_lock_time_gives_csv(self):
        assert self._opcode(TxLockTypes.SEQUENCE_LOCK_TIME) == "csv"

    def test_abs_lock_blocks_gives_cltv(self):
        assert self._opcode(TxLockTypes.ABS_LOCK_BLOCKS) == "cltv"

    def test_abs_lock_time_gives_cltv(self):
        assert self._opcode(TxLockTypes.ABS_LOCK_TIME) == "cltv"

class TestBuildParseHtlcImportPayload(unittest.TestCase):
    """Round-trip tests for _buildHtlcImportPayload / _parseHtlcImportMsg."""

    def _roundtrip(self):
        bid_id = bytes(range(28))
        blinding_key = 0xABCD1234 * (2 ** 224)
        lock_value = 12345
        nav_addr_redeem = "NVredeem"
        nav_addr_refund = "NVrefund"
        chain_height = 800
        txn_funded = "deadbeef" * 8

        payload_hex = NAVInterface._buildHtlcImportPayload(
            MessageTypes.NAV_ITX_IMPORT,
            bid_id, blinding_key, lock_value,
            nav_addr_redeem, nav_addr_refund, chain_height, txn_funded,
        )
        msg_bytes = bytes.fromhex(payload_hex[2:])  # skip 1-byte msg_type prefix
        parsed = NAVInterface._parseHtlcImportMsg(msg_bytes)
        p_bid_id, p_blinding_key, p_lock_value, p_addr_redeem, p_addr_refund, p_rescan_from, p_tx = parsed

        assert p_bid_id == bid_id
        assert p_blinding_key == blinding_key
        assert p_lock_value == lock_value
        assert p_addr_redeem == nav_addr_redeem
        assert p_addr_refund == nav_addr_refund
        assert p_rescan_from == chain_height
        assert p_tx == bytes.fromhex(txn_funded)

    def test_roundtrip(self):
        self._roundtrip()

class TestBuildImportBlsctScriptParams(unittest.TestCase):
    def test_fields_and_types(self):
        secret_hash = bytes(range(32))
        blinding_key = 0xABCD1234
        params = NAVInterface._buildImportBlsctScriptParams(
            "NVredeem", "NVrefund", secret_hash, 12345, blinding_key,
        )
        assert params["type"] == "atomic_swap"
        assert params["address_a"] == "NVredeem"
        assert params["address_b"] == "NVrefund"
        assert params["hash"] == secret_hash.hex()
        assert params["locktime"] == 12345
        assert params["timelock_opcode"] == "cltv"
        assert params["blinding_key"] == f"{blinding_key:064x}"

    def test_blinding_key_zero_padded(self):
        params = NAVInterface._buildImportBlsctScriptParams(
            "a", "b", bytes(32), 1, 1,
        )
        assert len(params["blinding_key"]) == 64
        assert params["blinding_key"] == "0" * 63 + "1"

if __name__ == "__main__":
    unittest.main()
