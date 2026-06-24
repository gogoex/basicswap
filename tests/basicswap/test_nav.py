#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (c) 2025 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import unittest

from coincurve.keys import PrivateKey

from basicswap.basicswap_util import TxLockTypes
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

class TestIsHTLCTxnSpent(unittest.TestCase):
    """Tests for isHTLCTxnSpent (RPCs stubbed)."""

    # Real HTLC spk that passes _isHTLCScript; secret_hash + lock_val (is_nav=True) below.
    HTLC_HEX = (
        "6382012088a820b812e53d1bd15a928803df44ab86c6a286d9a3d6625a3738f"
        "bed32d89a4c7c178830a7b9a59a0e305eef4f756909e6fa107091fc6d2b2743"
        "3d110d5d3c95ff987a0182bbd2e19897ee71af0466006cc2755467042c688b6"
        "9b17530a7b9a59a0e305eef4f756909e6fa107091fc6d2b27433d110d5d3c95"
        "ff987a0182bbd2e19897ee71af0466006cc2755468b3"
    )
    # A different valid HTLC spk (different secret_hash) for the no-match case.
    OTHER_HTLC_HEX = (
        "6382012088a8206756e66c48945a6851790e94fed56b86ec9d1e05116d4d289bf"
        "62f858389c3998830a6c43cded614e403d715cd7f28a57736214937dd811bd7e2927eed4cd"
        "904ee8df0066923c7dc021a36e94fa6f8fa21e36703710040b17530a769dfbee940c4f72c1"
        "29b5a315822dabda7932f5f12b8d1c56d2335544995504af3e11446a3b544cb6ec51403377"
        "33468b3"
    )

    def setUp(self):
        self.ci = ci_nav()
        spk = bytes.fromhex(self.HTLC_HEX)
        secret_hash = atomic_swap_1.extractScriptSecretHash(spk)
        lock_val = self.ci.extractHTLCLockVal(spk, is_nav=True)
        # bidder-side stored ITX script (non-NAV fake) sharing the same hash + locktime
        self.script = bytes(self.ci.createFakeNonNavHTLCScript(secret_hash, lock_val))

    def _stub(self, utxos, gettxout=None):
        self.ci._listBlsctUnspent = lambda: utxos
        self.ci.rpc = lambda method, params=None: gettxout

    def test_match_in_utxo_set_is_unspent(self):
        self._stub([{"scriptPubKey": self.HTLC_HEX, "outid": "abc"}], gettxout={"value": 1})
        assert self.ci.isHTLCTxnSpent(self.script) is False

    def test_match_not_in_utxo_set_is_spent(self):
        # gettxout returns empty → output confirmed-spent
        self._stub([{"scriptPubKey": self.HTLC_HEX, "outid": "abc"}], gettxout=None)
        assert self.ci.isHTLCTxnSpent(self.script) is True

    def test_match_no_outid_falls_back_to_unspent(self):
        self._stub([{"scriptPubKey": self.HTLC_HEX}])
        assert self.ci.isHTLCTxnSpent(self.script) is False

    def test_no_matching_htlc_is_spent(self):
        # Different HTLC script (different secret_hash) → no match → spent
        self._stub([{"scriptPubKey": self.OTHER_HTLC_HEX, "outid": "abc"}])
        assert self.ci.isHTLCTxnSpent(self.script) is True

    def test_non_htlc_utxos_skipped_is_spent(self):
        self._stub([{"scriptPubKey": "76a91488ac", "outid": "x"}, {"scriptPubKey": "", "outid": "y"}])
        assert self.ci.isHTLCTxnSpent(self.script) is True

    def test_empty_utxo_list_is_spent(self):
        self._stub([])
        assert self.ci.isHTLCTxnSpent(self.script) is True

    def test_exception_returns_false(self):
        def boom():
            raise RuntimeError("rpc down")
        self.ci._listBlsctUnspent = boom
        assert self.ci.isHTLCTxnSpent(self.script) is False

class TestGetPrevOutInfoFromChain(unittest.TestCase):
    """Tests for getPrevOutInfoFromChain (listblsctunspent stubbed)."""

    HTLC_HEX = TestIsHTLCTxnSpent.HTLC_HEX
    OTHER_HTLC_HEX = TestIsHTLCTxnSpent.OTHER_HTLC_HEX

    def setUp(self):
        self.ci = ci_nav()
        spk = bytes.fromhex(self.HTLC_HEX)
        self.secret_hash = atomic_swap_1.extractScriptSecretHash(spk)
        self.lock_val = self.ci.extractHTLCLockVal(spk, is_nav=True)

    def _stub(self, utxos):
        self.ci._listBlsctUnspent = lambda: utxos

    def test_match_returns_prevout(self):
        self._stub([{"scriptPubKey": self.HTLC_HEX, "outid": "abc", "amount": 1.5, "gamma": "gg"}])
        prevout = self.ci.getPrevOutInfoFromChain(self.secret_hash, self.lock_val)
        assert prevout == {"outid": "abc", "amount": 1.5, "gamma": "gg"}

    def test_outputHash_fallback_when_no_outid(self):
        self._stub([{"scriptPubKey": self.HTLC_HEX, "outputHash": "deadbeef", "amount": 2, "gamma": "g"}])
        prevout = self.ci.getPrevOutInfoFromChain(self.secret_hash, self.lock_val)
        assert prevout["outid"] == "deadbeef"

    def test_lock_val_mismatch_raises(self):
        self._stub([{"scriptPubKey": self.HTLC_HEX, "outid": "abc", "amount": 1, "gamma": "g"}])
        with self.assertRaises(ValueError):
            self.ci.getPrevOutInfoFromChain(self.secret_hash, self.lock_val + 1)

    def test_secret_hash_mismatch_raises(self):
        self._stub([{"scriptPubKey": self.OTHER_HTLC_HEX, "outid": "abc", "amount": 1, "gamma": "g"}])
        with self.assertRaises(ValueError):
            self.ci.getPrevOutInfoFromChain(self.secret_hash, self.lock_val)

    def test_non_htlc_utxos_skipped_raises(self):
        self._stub([{"scriptPubKey": "76a91488ac", "outid": "x", "amount": 1, "gamma": "g"}])
        with self.assertRaises(ValueError):
            self.ci.getPrevOutInfoFromChain(self.secret_hash, self.lock_val)

    def test_empty_utxo_list_raises(self):
        self._stub([])
        with self.assertRaises(ValueError):
            self.ci.getPrevOutInfoFromChain(self.secret_hash, self.lock_val)

if __name__ == "__main__":
    unittest.main()
