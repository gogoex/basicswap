#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (c) 2025 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import unittest

from coincurve.keys import PrivateKey

import types

from basicswap.basicswap_util import (
    EventLogTypes,
    SwapTypes,
    TxLockTypes,
    TxStates,
)
from basicswap.basicswap import BasicSwap
from basicswap.chainparams import Coins
from basicswap.interface.nav.nav import NAVInterface
from basicswap.util import TemporaryError
import basicswap.protocols.atomic_swap_1 as atomic_swap_1
import basicswap.protocols.nav_swap_1 as nav_swap_1
from tests.basicswap.util.common import REQUIRED_SETTINGS


def ci_nav():
    settings = {"rpcport": 0, "rpcauth": "none"}
    settings.update(REQUIRED_SETTINGS)
    # Build through BasicSwap's coin interface factory, so a missing or broken
    # Coins.NAV branch in createInterface fails these tests.
    swap_client = types.SimpleNamespace(
        coin_clients={Coins.NAV: settings},
        chain="regtest",
        log=None,
        settings={},
        getBaseAltruistic=lambda: True,
        getChainClientSettings=lambda coin_type: {},
    )
    ci = BasicSwap.createInterface(swap_client, Coins.NAV)
    assert isinstance(ci, NAVInterface)
    return ci


class TestFakeHTLCScript(unittest.TestCase):
    """Tests for createFakeNonNavHTLCScript and extractHTLCLockVal."""

    def setUp(self):
        self.ci = ci_nav()
        self.secret_hash = bytes(32)

    def test_roundtrip_block_heights(self):
        for lock_value in (1, 100, 123456, 499_999_999):
            script = self.ci.createFakeNonNavHTLCScript(self.secret_hash, lock_value)
            assert (
                self.ci.extractHTLCLockVal(bytes(script), is_nav=False) == lock_value
            ), lock_value

    def test_roundtrip_timestamps(self):
        for lock_value in (500_000_000, 1_700_000_000, 1_800_000_000):
            script = self.ci.createFakeNonNavHTLCScript(self.secret_hash, lock_value)
            assert (
                self.ci.extractHTLCLockVal(bytes(script), is_nav=False) == lock_value
            ), lock_value

    def test_secret_hash_preserved(self):
        secret_hash = bytes(range(32))
        script = self.ci.createFakeNonNavHTLCScript(secret_hash, 123456)
        extracted = atomic_swap_1.extractScriptSecretHash(bytes(script))
        assert extracted == secret_hash

    def test_short_secret_hash_padded(self):
        # extractScriptSecretHash must still recover correct hash after rjust padding
        secret_hash = b"\x01" * 20
        script = self.ci.createFakeNonNavHTLCScript(secret_hash, 100)
        extracted = atomic_swap_1.extractScriptSecretHash(bytes(script))
        assert extracted == secret_hash.rjust(32, b"\x00")


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
        self.privA = bytes.fromhex(
            "e6b8e7c2ca3a88fe4f28591aa0f91fec340179346559e4ec430c2531aecc19aa"
        )
        self.privB = bytes.fromhex(
            "b725b6359bd2b510d9d5a7bba7bdee17abbf113253f6338ea50a8f0cf45fd0d0"
        )
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
        privC = bytes.fromhex(
            "0b4c6e34c21b910f92c7985a8093de526f5f8677a112a8c672d1098139b70e0f"
        )
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
        assert (
            self.ci.isTxNonFinalError("sendrawtransaction: non-final-input (code 64)")
            is True
        )

    def test_bad_input_unknown(self):
        assert self.ci.isTxNonFinalError("bad-input-unknown") is True
        assert self.ci.isTxNonFinalError("bad-inputs-unknown") is True

    def test_code_25(self):
        assert (
            self.ci.isTxNonFinalError("{'code': 25, 'message': 'Missing inputs'}")
            is True
        )

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


class TestGetLockValue(unittest.TestCase):
    """getLockValue: absolute timestamp vs block-height CLTV, ITX vs PTX duration."""

    NOW = 1_700_000_000
    HEIGHT = 2_000_000

    def _ci(self):
        ci = ci_nav()
        ci.getChainHeight = lambda: self.HEIGHT
        ci._sc = types.SimpleNamespace(getTime=lambda: self.NOW)
        return ci

    def _offer(self, lock_type, lock_value):
        return types.SimpleNamespace(lock_type=lock_type, lock_value=lock_value)

    def test_abs_lock_time_initiate_uses_timestamp(self):
        ci = self._ci()
        offer = self._offer(TxLockTypes.ABS_LOCK_TIME, 3600)
        assert ci.getLockValue(offer, is_initiate=True) == self.NOW + 3600

    def test_abs_lock_time_participate_is_half(self):
        ci = self._ci()
        offer = self._offer(TxLockTypes.ABS_LOCK_TIME, 3600)
        assert ci.getLockValue(offer, is_initiate=False) == self.NOW + 1800

    def test_abs_lock_blocks_initiate_uses_height(self):
        ci = self._ci()
        offer = self._offer(TxLockTypes.ABS_LOCK_BLOCKS, 100)
        assert ci.getLockValue(offer, is_initiate=True) == self.HEIGHT + 100

    def test_abs_lock_blocks_participate_is_half(self):
        ci = self._ci()
        offer = self._offer(TxLockTypes.ABS_LOCK_BLOCKS, 100)
        assert ci.getLockValue(offer, is_initiate=False) == self.HEIGHT + 50


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

    def _stub(self, utxos, gettxout=None, confirmations=1):
        self.ci._listBlsctUnspent = lambda: utxos
        self.ci.rpc = lambda method, params=None: gettxout

        def getblsctoutput(method, params=None):
            assert method == "getblsctoutput"
            if confirmations is None:
                raise RuntimeError("Output not found")
            return {"confirmations": confirmations}

        self.ci.rpc_wallet = getblsctoutput

    def test_match_in_utxo_set_is_unspent(self):
        self._stub(
            [{"scriptPubKey": self.HTLC_HEX, "outid": "abc"}], gettxout={"value": 1}
        )
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
        self._stub(
            [
                {"scriptPubKey": "76a91488ac", "outid": "x"},
                {"scriptPubKey": "", "outid": "y"},
            ]
        )
        assert self.ci.isHTLCTxnSpent(self.script) is True

    def test_empty_utxo_list_is_spent(self):
        self._stub([])
        assert self.ci.isHTLCTxnSpent(self.script) is True

    def test_not_listed_spent_in_mempool_only_is_unspent(self):
        # Wallet drops the output once its spend is in the mempool, gettxout with
        # include_mempool=False still returns it until the spend is mined
        self._stub([], gettxout={"value": 1})
        assert self.ci.isHTLCTxnSpent(self.script, bytes.fromhex("ab")) is False

    def test_not_listed_spend_mined_is_spent(self):
        self._stub([], gettxout=None)
        assert self.ci.isHTLCTxnSpent(self.script, bytes.fromhex("ab")) is True

    # gettxout with include_mempool=False returns nothing for an output not mined
    # yet, getblsctoutput's confirmations tell it apart from a spent one
    def test_listed_not_mined_is_unspent(self):
        self._stub(
            [{"scriptPubKey": self.HTLC_HEX, "outid": "abc"}],
            gettxout=None,
            confirmations=0,
        )
        assert self.ci.isHTLCTxnSpent(self.script) is False

    def test_not_listed_not_mined_is_unspent(self):
        self._stub([], gettxout=None, confirmations=0)
        assert self.ci.isHTLCTxnSpent(self.script, bytes.fromhex("ab")) is False

    def test_not_listed_unknown_output_is_unspent(self):
        # getblsctoutput fails: not known to be mined, so not reported spent
        self._stub([], gettxout=None, confirmations=None)
        assert self.ci.isHTLCTxnSpent(self.script, bytes.fromhex("ab")) is False

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

    def _stub(self, utxos):
        self.ci._listBlsctUnspent = lambda: utxos

    def test_match_returns_prevout(self):
        self._stub(
            [
                {
                    "scriptPubKey": self.HTLC_HEX,
                    "outid": "abc",
                    "amount": 1.5,
                    "gamma": "gg",
                }
            ]
        )
        prevout = self.ci.getPrevOutInfoFromChain(self.secret_hash)
        assert prevout == {"outid": "abc", "amount": 1.5, "gamma": "gg"}

    def test_outputHash_fallback_when_no_outid(self):
        self._stub(
            [
                {
                    "scriptPubKey": self.HTLC_HEX,
                    "outputHash": "deadbeef",
                    "amount": 2,
                    "gamma": "g",
                }
            ]
        )
        prevout = self.ci.getPrevOutInfoFromChain(self.secret_hash)
        assert prevout["outid"] == "deadbeef"

    def test_secret_hash_mismatch_raises(self):
        self._stub(
            [
                {
                    "scriptPubKey": self.OTHER_HTLC_HEX,
                    "outid": "abc",
                    "amount": 1,
                    "gamma": "g",
                }
            ]
        )
        with self.assertRaises(ValueError):
            self.ci.getPrevOutInfoFromChain(self.secret_hash)

    def test_non_htlc_utxos_skipped_raises(self):
        self._stub(
            [{"scriptPubKey": "76a91488ac", "outid": "x", "amount": 1, "gamma": "g"}]
        )
        with self.assertRaises(ValueError):
            self.ci.getPrevOutInfoFromChain(self.secret_hash)

    def test_empty_utxo_list_raises(self):
        self._stub([])
        with self.assertRaises(ValueError):
            self.ci.getPrevOutInfoFromChain(self.secret_hash)


def _mk_bid(
    *, ptx_state=None, itx_state=None, was_received=False, has_ptx=True, has_itx=True
):
    b = types.SimpleNamespace(
        was_received=was_received,
        participate_tx=(
            types.SimpleNamespace(script=b"ptx", txid=None) if has_ptx else None
        ),
        initiate_tx=(
            types.SimpleNamespace(script=b"itx", txid=None) if has_itx else None
        ),
    )
    b._ptx = ptx_state
    b._itx = itx_state
    b.getPTxState = lambda: b._ptx
    b.getITxState = lambda: b._itx

    def set_ptx(s):
        b._ptx = s

    def set_itx(s):
        b._itx = s

    b.setPTxState = set_ptx
    b.setITxState = set_itx
    return b


def _ev(event_type):
    return types.SimpleNamespace(event_type=int(event_type))


class TestHandleSwapParticipatingLabel(unittest.TestCase):
    """handleSwapParticipating: redeem vs refund labelling on a NAV HTLC spend.

    BLSCT hides the preimage on-chain, so the state is inferred from this node's
    own recorded action then its role. Roles are reversed between legs: the
    offerer is the redeem party of the PTX but the refund party of the ITX.
    """

    def setUp(self):
        self.ci = ci_nav()
        self.ci.isHTLCTxnSpent = lambda script, outid=None: True  # spent

    def _run(self, bid, coin_from, coin_to, events):
        self.ci._sc = types.SimpleNamespace(getEvents=lambda ct, bid_id: events)
        return self.ci.handleSwapParticipating(b"bid", bid, coin_from, coin_to)

    # ---- PTX (coin_to == NAV): offerer = redeem, bidder = refund ----
    def test_ptx_own_refund_event(self):
        bid = _mk_bid(ptx_state=TxStates.TX_CONFIRMED)
        assert (
            self._run(
                bid, Coins.LTC, Coins.NAV, [_ev(EventLogTypes.PTX_REFUND_PUBLISHED)]
            )
            is True
        )
        assert bid.getPTxState() == TxStates.TX_REFUNDED

    def test_ptx_own_redeem_event(self):
        bid = _mk_bid(ptx_state=TxStates.TX_CONFIRMED)
        self._run(bid, Coins.LTC, Coins.NAV, [_ev(EventLogTypes.PTX_REDEEM_PUBLISHED)])
        assert bid.getPTxState() == TxStates.TX_REDEEMED

    def test_ptx_offerer_no_event_is_refund(self):
        # offerer (was_received) didn't redeem -> bidder refunded
        bid = _mk_bid(ptx_state=TxStates.TX_CONFIRMED, was_received=True)
        self._run(bid, Coins.LTC, Coins.NAV, [])
        assert bid.getPTxState() == TxStates.TX_REFUNDED

    def test_ptx_bidder_no_event_is_redeem(self):
        # bidder (was_sent) didn't refund -> offerer redeemed
        bid = _mk_bid(ptx_state=TxStates.TX_CONFIRMED, was_received=False)
        self._run(bid, Coins.LTC, Coins.NAV, [])
        assert bid.getPTxState() == TxStates.TX_REDEEMED

    def test_ptx_guard_skips_when_already_terminal(self):
        bid = _mk_bid(ptx_state=TxStates.TX_REFUNDED, was_received=True)
        assert self._run(bid, Coins.LTC, Coins.NAV, []) is False
        assert bid.getPTxState() == TxStates.TX_REFUNDED  # unchanged, no re-append

    def test_ptx_not_spent_no_change(self):
        self.ci.isHTLCTxnSpent = lambda script, outid=None: False
        bid = _mk_bid(ptx_state=TxStates.TX_CONFIRMED, was_received=True)
        assert self._run(bid, Coins.LTC, Coins.NAV, []) is False
        assert bid.getPTxState() == TxStates.TX_CONFIRMED

    # ---- ITX (coin_from == NAV): offerer = refund, bidder = redeem ----
    def test_itx_own_refund_event(self):
        bid = _mk_bid(itx_state=TxStates.TX_CONFIRMED)
        assert (
            self._run(
                bid, Coins.NAV, Coins.LTC, [_ev(EventLogTypes.ITX_REFUND_PUBLISHED)]
            )
            is True
        )
        assert bid.getITxState() == TxStates.TX_REFUNDED

    def test_itx_own_redeem_event(self):
        bid = _mk_bid(itx_state=TxStates.TX_CONFIRMED)
        self._run(bid, Coins.NAV, Coins.LTC, [_ev(EventLogTypes.ITX_REDEEM_PUBLISHED)])
        assert bid.getITxState() == TxStates.TX_REDEEMED

    def test_itx_offerer_no_event_is_redeem(self):
        # offerer (was_received) owns the ITX; didn't refund -> bidder redeemed
        bid = _mk_bid(itx_state=TxStates.TX_CONFIRMED, was_received=True)
        self._run(bid, Coins.NAV, Coins.LTC, [])
        assert bid.getITxState() == TxStates.TX_REDEEMED

    def test_itx_bidder_no_event_is_refund(self):
        # bidder (was_sent) didn't redeem -> offerer refunded
        bid = _mk_bid(itx_state=TxStates.TX_CONFIRMED, was_received=False)
        self._run(bid, Coins.NAV, Coins.LTC, [])
        assert bid.getITxState() == TxStates.TX_REFUNDED

    def test_itx_guard_skips_when_already_terminal(self):
        bid = _mk_bid(itx_state=TxStates.TX_REDEEMED, was_received=True)
        assert self._run(bid, Coins.NAV, Coins.LTC, []) is False


class TestHtlcSpendInMempool(unittest.TestCase):
    """A NAV HTLC spend must not be recorded until it is mined.

    Regression: in a NAV->LTC refund test both nodes marked the ITX TX_REFUNDED
    and completed the swap while the refund was only in the mempool:
    listblsctunspent drops an output as soon as its spend is in the mempool and
    gettxout hides it with the default include_mempool=true.
    """

    HTLC_HEX = TestIsHTLCTxnSpent.HTLC_HEX
    OUTID = bytes.fromhex(
        "b8b624c618200a42dc4a91912086dcee0cc37b2e9c4f63d674914c6bb76be210"
    )

    def setUp(self):
        self.ci = ci_nav()
        spk = bytes.fromhex(self.HTLC_HEX)
        secret_hash = atomic_swap_1.extractScriptSecretHash(spk)
        lock_val = self.ci.extractHTLCLockVal(spk, is_nav=True)
        self.script = bytes(self.ci.createFakeNonNavHTLCScript(secret_hash, lock_val))
        self.mined = False
        self.listed = False

        def fake_rpc(method, params=None):
            # navio gettxout: an output spent in the mempool is hidden unless
            # include_mempool is false, an output spent in a block is always gone
            assert method == "gettxout"
            include_mempool = params[1] if len(params) > 1 else True
            if self.mined or include_mempool:
                return None
            return {"value": 1}

        self.ci.rpc = fake_rpc
        # the HTLC output itself was mined before the spend
        self.ci.rpc_wallet = lambda method, params=None: {"confirmations": 1}
        self.ci._listBlsctUnspent = lambda: (
            [{"scriptPubKey": self.HTLC_HEX, "outid": self.OUTID.hex()}]
            if self.listed
            else []
        )

    def _bid(self, was_received, leg):
        bid = _mk_bid(
            itx_state=TxStates.TX_CONFIRMED if leg == "itx" else None,
            ptx_state=TxStates.TX_CONFIRMED if leg == "ptx" else None,
            was_received=was_received,
        )
        tx = bid.initiate_tx if leg == "itx" else bid.participate_tx
        tx.script = self.script
        tx.txid = self.OUTID
        return bid

    def _run(self, bid, coin_from, coin_to, events):
        self.ci._sc = types.SimpleNamespace(getEvents=lambda ct, bid_id: events)
        return self.ci.handleSwapParticipating(b"bid", bid, coin_from, coin_to)

    def _check(self, was_received, leg, events, expected):
        # NAV->LTC: NAV is the ITX leg, LTC->NAV: NAV is the PTX leg
        coin_from, coin_to = (
            (Coins.NAV, Coins.LTC) if leg == "itx" else (Coins.LTC, Coins.NAV)
        )
        bid = self._bid(was_received, leg)
        get_state = bid.getITxState if leg == "itx" else bid.getPTxState
        # spend in the mempool only: nothing recorded yet
        assert self._run(bid, coin_from, coin_to, events) is False
        assert get_state() == TxStates.TX_CONFIRMED
        # spend mined
        self.mined = True
        assert self._run(bid, coin_from, coin_to, events) is True
        assert get_state() == expected

    # NAV->LTC, offerer doesn't redeem the PTX: offerer refunds the NAV ITX
    def test_nav_ltc_offerer_no_redeem_offerer(self):
        events = [_ev(EventLogTypes.ITX_REFUND_PUBLISHED)]
        self._check(True, "itx", events, TxStates.TX_REFUNDED)

    def test_nav_ltc_offerer_no_redeem_bidder(self):
        self._check(False, "itx", [], TxStates.TX_REFUNDED)

    # NAV->LTC, bidder doesn't redeem the ITX: offerer refunds the NAV ITX
    def test_nav_ltc_bidder_no_redeem_offerer(self):
        events = [
            _ev(EventLogTypes.PTX_REDEEM_PUBLISHED),
            _ev(EventLogTypes.ITX_REFUND_PUBLISHED),
        ]
        self._check(True, "itx", events, TxStates.TX_REFUNDED)

    def test_nav_ltc_bidder_no_redeem_bidder(self):
        self._check(False, "itx", [], TxStates.TX_REFUNDED)

    # LTC->NAV, offerer doesn't redeem the PTX: bidder refunds the NAV PTX
    def test_ltc_nav_offerer_no_redeem_offerer(self):
        self._check(True, "ptx", [], TxStates.TX_REFUNDED)

    def test_ltc_nav_offerer_no_redeem_bidder(self):
        events = [_ev(EventLogTypes.PTX_REFUND_PUBLISHED)]
        self._check(False, "ptx", events, TxStates.TX_REFUNDED)

    # LTC->NAV, bidder doesn't redeem the ITX: offerer redeemed the NAV PTX
    def test_ltc_nav_bidder_no_redeem_offerer(self):
        events = [_ev(EventLogTypes.PTX_REDEEM_PUBLISHED)]
        self._check(True, "ptx", events, TxStates.TX_REDEEMED)

    def test_ltc_nav_bidder_no_redeem_bidder(self):
        self._check(False, "ptx", [], TxStates.TX_REDEEMED)

    def test_listed_output_spent_in_mempool_is_unspent(self):
        # watch-only wallet keeps listing the output, gettxout must ignore the mempool
        self.listed = True
        self._check(False, "itx", [], TxStates.TX_REFUNDED)


class TestSwapEventOrder(unittest.TestCase):
    """Replays each refund case on each node in the order the live tests produced
    its events, and checks when the NAV leg changes state.

    Each step publishes events (or delivers the preimage), moves the NAV HTLC
    spend along (unspent, in the mempool, mined), then runs
    handleSwapParticipating as checkBidState does in SWAP_PARTICIPATING. The NAV
    leg must change state exactly once, at the step its spend is mined.
    """

    HTLC_HEX = TestHtlcSpendInMempool.HTLC_HEX
    OUTID = TestHtlcSpendInMempool.OUTID
    BID_ID = bytes(range(28))
    SECRET = bytes(32)

    UNSPENT, MEMPOOL, MINED = "unspent", "mempool", "mined"
    PREIMAGE = "preimage"  # offerer's NAV_HTLC_PREIMAGE message arrives

    ITX_REFUND = EventLogTypes.ITX_REFUND_PUBLISHED
    PTX_REDEEM = EventLogTypes.PTX_REDEEM_PUBLISHED
    PTX_REFUND = EventLogTypes.PTX_REFUND_PUBLISHED

    def setUp(self):
        # same fake navio node as TestHtlcSpendInMempool
        TestHtlcSpendInMempool.setUp(self)
        self.events = []
        self.swaps_in_progress = {}
        log = types.SimpleNamespace(
            id=lambda x: x,
            info=lambda *a, **k: None,
            warning=lambda *a, **k: None,
            debug=lambda *a, **k: None,
        )
        self.ci._sc = types.SimpleNamespace(
            getEvents=lambda ct, bid_id: list(self.events),
            getSmsgMsgBytes=lambda msg: msg,
            swaps_in_progress=self.swaps_in_progress,
            get_short_delay_event_seconds=lambda: 0,
            createAction=lambda delay, action_type, bid_id: None,
            saveBid=lambda bid_id, bid: None,
            log=log,
        )

    def _replay(self, was_received, leg, steps, initiated=False):
        """Return the NAV leg's state changes as (step index, new state).

        initiated: the bid is still in SWAP_INITIATED with the PTX TX_SENT, so
        detectNavPtxSpend runs instead of handleSwapParticipating.
        """
        coin_from, coin_to = (
            (Coins.NAV, Coins.LTC) if leg == "itx" else (Coins.LTC, Coins.NAV)
        )
        bid = TestHtlcSpendInMempool._bid(self, was_received, leg)
        bid.bid_id = self.BID_ID
        if initiated:
            bid._ptx = TxStates.TX_SENT
        self.swaps_in_progress[self.BID_ID] = (bid, None)

        changes = []
        step_no = [0]
        attr = "setITxState" if leg == "itx" else "setPTxState"
        set_state = getattr(bid, attr)

        def record(state):
            changes.append((step_no[0], state))
            set_state(state)

        setattr(bid, attr, record)

        for i, (spend, *items) in enumerate(steps):
            step_no[0] = i
            self.listed = spend == self.UNSPENT
            self.mined = spend == self.MINED
            for item in items:
                if item == self.PREIMAGE:
                    self.ci.processNavHtlcPreimage(self.BID_ID + self.SECRET)
                else:
                    self.events.append(_ev(item))
            if initiated:
                self.ci.detectNavPtxSpend(bid.bid_id, bid, coin_from)
            else:
                self.ci.handleSwapParticipating(bid.bid_id, bid, coin_from, coin_to)
        return changes

    # NAV->LTC, offerer doesn't redeem the PTX: offerer refunds the NAV ITX
    def test_nav_ltc_offerer_no_redeem_offerer(self):
        steps = [
            (self.UNSPENT,),
            (self.MEMPOOL, self.ITX_REFUND),
            (self.MINED,),
            (self.MINED,),
        ]
        changes = self._replay(True, "itx", steps)
        assert changes == [(2, TxStates.TX_REFUNDED)], changes

    def test_nav_ltc_offerer_no_redeem_bidder(self):
        # the bidder refunds the LTC PTX first, it must not affect the NAV ITX
        steps = [
            (self.UNSPENT, self.PTX_REFUND),
            (self.MEMPOOL,),
            (self.MINED,),
            (self.MINED,),
        ]
        changes = self._replay(False, "itx", steps)
        assert changes == [(2, TxStates.TX_REFUNDED)], changes

    # NAV->LTC, bidder doesn't redeem the ITX: offerer redeems the LTC PTX,
    # then refunds the NAV ITX
    def test_nav_ltc_bidder_no_redeem_offerer(self):
        steps = [
            (self.UNSPENT, self.PTX_REDEEM),
            (self.MEMPOOL, self.ITX_REFUND),
            (self.MINED,),
            (self.MINED,),
        ]
        changes = self._replay(True, "itx", steps)
        assert changes == [(2, TxStates.TX_REFUNDED)], changes

    def test_nav_ltc_bidder_no_redeem_bidder(self):
        steps = [(self.UNSPENT,), (self.MEMPOOL,), (self.MINED,), (self.MINED,)]
        changes = self._replay(False, "itx", steps)
        assert changes == [(2, TxStates.TX_REFUNDED)], changes

    # LTC->NAV, offerer doesn't redeem the PTX: bidder refunds the NAV PTX,
    # later the offerer refunds the LTC ITX
    def test_ltc_nav_offerer_no_redeem_offerer(self):
        steps = [
            (self.UNSPENT,),
            (self.MEMPOOL,),
            (self.MINED,),
            (self.MINED, self.ITX_REFUND),
        ]
        changes = self._replay(True, "ptx", steps)
        assert changes == [(2, TxStates.TX_REFUNDED)], changes

    def test_ltc_nav_offerer_no_redeem_bidder(self):
        steps = [
            (self.UNSPENT,),
            (self.MEMPOOL, self.PTX_REFUND),
            (self.MINED,),
            (self.MINED, self.ITX_REFUND),
        ]
        changes = self._replay(False, "ptx", steps)
        assert changes == [(2, TxStates.TX_REFUNDED)], changes

    # LTC->NAV, bidder doesn't redeem the ITX: offerer redeems the NAV PTX,
    # later refunds the LTC ITX
    def test_ltc_nav_bidder_no_redeem_offerer(self):
        steps = [
            (self.UNSPENT,),
            (self.MEMPOOL, self.PTX_REDEEM),
            (self.MINED,),
            (self.MINED, self.ITX_REFUND),
        ]
        changes = self._replay(True, "ptx", steps)
        assert changes == [(2, TxStates.TX_REDEEMED)], changes

    def test_ltc_nav_bidder_no_redeem_bidder_no_preimage(self):
        steps = [
            (self.UNSPENT,),
            (self.MEMPOOL,),
            (self.MINED,),
            (self.MINED, self.ITX_REFUND),
        ]
        changes = self._replay(False, "ptx", steps)
        assert changes == [(2, TxStates.TX_REDEEMED)], changes

    def test_ltc_nav_bidder_no_redeem_bidder(self):
        # the preimage arrives while the offerer's redeem is still in the
        # mempool, the PTX must wait for the redeem to be mined
        steps = [
            (self.UNSPENT,),
            (self.MEMPOOL, self.PREIMAGE),
            (self.MINED,),
            (self.MINED, self.ITX_REFUND),
        ]
        changes = self._replay(False, "ptx", steps)
        assert changes == [(2, TxStates.TX_REDEEMED)], changes

    def test_ltc_nav_bidder_no_redeem_bidder_stuck_initiated(self):
        # the offerer's redeem reached the mempool before the bidder saw its PTX
        # confirm, so the bid stays in SWAP_INITIATED and detectNavPtxSpend runs
        steps = [
            (self.MEMPOOL, self.PREIMAGE),
            (self.MEMPOOL,),
            (self.MINED,),
            (self.MINED, self.ITX_REFUND),
        ]
        changes = self._replay(False, "ptx", steps, initiated=True)
        assert changes == [(2, TxStates.TX_REDEEMED)], changes


class TestDetectNavItxSpend(unittest.TestCase):
    """detectNavItxSpend records an ITX spend seen in SWAP_INITIATED.

    The ITX HTLC output has two spenders (bidder redeem, offerer refund). This
    early detector runs before handleSwapParticipating; when our own redeem
    spends the ITX it must be recorded as TX_REDEEMED, not TX_REFUNDED. The bid
    can stay in SWAP_INITIATED if the PTX was spent before this node saw it
    confirmed, so handleSwapParticipating may never run.
    """

    def setUp(self):
        self.ci = ci_nav()
        self.ci.isHTLCTxnSpent = lambda script, outid=None: True  # spent

    def _run(self, bid, events):
        self.ci._sc = types.SimpleNamespace(
            getEvents=lambda ct, bid_id: events,
            log=types.SimpleNamespace(id=lambda x: x, info=lambda *a, **k: None),
        )
        return self.ci.detectNavItxSpend(bid)

    def test_spent_with_own_redeem_event_is_redeemed(self):
        # Regression: our own redeem spent the ITX, bid stuck in SWAP_INITIATED.
        bid = _mk_bid(itx_state=TxStates.TX_CONFIRMED)
        bid.bid_id = b"bid"
        assert self._run(bid, [_ev(EventLogTypes.ITX_REDEEM_PUBLISHED)]) is True
        assert bid.getITxState() == TxStates.TX_REDEEMED

    def test_spent_without_redeem_event_is_refund(self):
        bid = _mk_bid(itx_state=TxStates.TX_CONFIRMED)
        bid.bid_id = b"bid"
        assert self._run(bid, []) is True
        assert bid.getITxState() == TxStates.TX_REFUNDED

    def test_not_spent_no_change(self):
        self.ci.isHTLCTxnSpent = lambda script, outid=None: False
        bid = _mk_bid(itx_state=TxStates.TX_CONFIRMED)
        bid.bid_id = b"bid"
        assert self._run(bid, []) is False
        assert bid.getITxState() == TxStates.TX_CONFIRMED

    def test_terminal_state_skipped(self):
        bid = _mk_bid(itx_state=TxStates.TX_REDEEMED)
        bid.bid_id = b"bid"
        assert self._run(bid, []) is False


class TestDetectNavPtxSpend(unittest.TestCase):
    """detectNavPtxSpend records a NAV PTX spend seen in SWAP_INITIATED.

    The bidder can miss its PTX confirming when the offerer's redeem reaches the
    mempool first, so the bid never reaches SWAP_PARTICIPATING. The PTX must
    still be marked, and only once the spend is mined.
    """

    HTLC_HEX = TestHtlcSpendInMempool.HTLC_HEX
    OUTID = TestHtlcSpendInMempool.OUTID

    def setUp(self):
        # same fake navio node as TestHtlcSpendInMempool, spend mined
        TestHtlcSpendInMempool.setUp(self)
        self.mined = True
        self.events = []
        self.ci._sc = types.SimpleNamespace(getEvents=lambda ct, bid_id: self.events)

    def _bid(self, was_received, state):
        bid = TestHtlcSpendInMempool._bid(self, was_received, "ptx")
        bid._ptx = state
        return bid

    def _run(self, bid):
        return self.ci.detectNavPtxSpend(b"bid", bid, Coins.LTC)

    def test_bidder_sent_spend_mined_is_redeemed(self):
        bid = self._bid(False, TxStates.TX_SENT)
        assert self._run(bid) is True
        assert bid.getPTxState() == TxStates.TX_REDEEMED

    def test_offerer_own_redeem_is_redeemed(self):
        self.events = [_ev(EventLogTypes.PTX_REDEEM_PUBLISHED)]
        bid = self._bid(True, TxStates.TX_CONFIRMED)
        assert self._run(bid) is True
        assert bid.getPTxState() == TxStates.TX_REDEEMED

    def test_spend_in_mempool_no_change(self):
        self.mined = False
        bid = self._bid(False, TxStates.TX_SENT)
        assert self._run(bid) is False
        assert bid.getPTxState() == TxStates.TX_SENT

    def test_ptx_not_mined_no_change(self):
        # gettxout returns nothing for an unmined output too
        self.ci.rpc_wallet = lambda method, params=None: {"confirmations": 0}
        bid = self._bid(False, TxStates.TX_SENT)
        assert self._run(bid) is False
        assert bid.getPTxState() == TxStates.TX_SENT

    def test_no_outid_no_change(self):
        bid = self._bid(False, TxStates.TX_SENT)
        bid.participate_tx.txid = None
        assert self._run(bid) is False
        assert bid.getPTxState() == TxStates.TX_SENT

    def test_unset_state_no_change(self):
        bid = self._bid(True, None)
        assert self._run(bid) is False
        assert bid.getPTxState() is None

    def test_terminal_state_skipped(self):
        bid = self._bid(False, TxStates.TX_REDEEMED)
        assert self._run(bid) is False
        assert bid.getPTxState() == TxStates.TX_REDEEMED


class TestProcessNavHtlcPreimageLength(unittest.TestCase):
    """processNavHtlcPreimage rejects a payload that isn't bid_id(28)+secret(32)."""

    def setUp(self):
        self.ci = ci_nav()

    def _run(self, payload):
        log = types.SimpleNamespace(
            id=lambda x: "id",
            info=lambda *a, **k: None,
            warning=lambda *a, **k: None,
            debug=lambda *a, **k: None,
        )
        self.ci._sc = types.SimpleNamespace(
            getSmsgMsgBytes=lambda msg: payload,
            log=log,
            swaps_in_progress={},
        )
        return self.ci.processNavHtlcPreimage({})

    def test_short_message_raises(self):
        with self.assertRaises(ValueError):
            self._run(b"\x00" * 59)

    def test_long_message_raises(self):
        with self.assertRaises(ValueError):
            self._run(b"\x00" * 61)

    def test_correct_length_passes_gate(self):
        # 60 bytes, bid not in progress -> returns gracefully (length gate passed)
        assert self._run(b"\x00" * 60) is None


class TestNavSwapRedeemITx(unittest.TestCase):
    """nav_swap_1.redeemITx: NAV wraps transient failures as TemporaryError so
    checkQueuedActions retries; non-NAV delegates unchanged."""

    def _swap(self, coin_from, coin_to):
        offer = types.SimpleNamespace(coin_from=int(coin_from), coin_to=int(coin_to))
        return types.SimpleNamespace(
            getBidAndOffer=lambda bid_id, cursor, with_txns: (None, offer)
        )

    def _patch_redeem(self, fn):
        self._orig = atomic_swap_1.redeemITx
        atomic_swap_1.redeemITx = fn

    def tearDown(self):
        if hasattr(self, "_orig"):
            atomic_swap_1.redeemITx = self._orig

    def test_non_nav_delegates(self):
        calls = []
        self._patch_redeem(lambda self, bid_id, cursor: calls.append("d") or "ok")
        r = nav_swap_1.redeemITx(self._swap(Coins.LTC, Coins.BTC), b"bid", None)
        assert calls == ["d"]
        assert r == "ok"

    def test_nav_success_returns(self):
        self._patch_redeem(lambda self, bid_id, cursor: "done")
        assert (
            nav_swap_1.redeemITx(self._swap(Coins.NAV, Coins.LTC), b"bid", None)
            == "done"
        )

    def test_nav_generic_exception_becomes_temporary(self):
        def boom(self, bid_id, cursor):
            raise RuntimeError("rpc down")

        self._patch_redeem(boom)
        with self.assertRaises(TemporaryError):
            nav_swap_1.redeemITx(self._swap(Coins.NAV, Coins.LTC), b"bid", None)

    def test_nav_temporary_error_not_double_wrapped(self):
        def boom(self, bid_id, cursor):
            raise TemporaryError("already temp")

        self._patch_redeem(boom)
        with self.assertRaises(TemporaryError) as cm:
            nav_swap_1.redeemITx(self._swap(Coins.NAV, Coins.LTC), b"bid", None)
        assert str(cm.exception) == "already temp"


class TestNavSwapInterface(unittest.TestCase):
    def test_swap_type_and_inheritance(self):
        iface = nav_swap_1.NavSwapInterface()
        assert iface.swap_type == SwapTypes.SECRET_HASH_BLSCT
        assert isinstance(iface, atomic_swap_1.AtomicSwapInterface)
        assert hasattr(iface, "getFundedInitiateTxTemplate")
        assert hasattr(iface, "promoteMockTx")


if __name__ == "__main__":
    unittest.main()
