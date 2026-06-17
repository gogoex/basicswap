# -*- coding: utf-8 -*-

# Copyright (c) 2023 tecnovert
# Copyright (c) 2024-2025 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from basicswap.interface.btc import (
    BTCInterface,
)
from basicswap.chainparams import Coins
from basicswap.db import Concepts, SwapTx
from typing import Optional, Any, TypedDict
from basicswap.basicswap_util import ActionTypes, BidStates, EventLogTypes, MessageTypes, TxLockTypes, TxStates, TxTypes
from basicswap.util import DeserialiseNum, SerialiseNum, TemporaryError, b2i, ensure
from basicswap.util.address import decodeWif
from basicswap.util.crypto import sha256
from coincurve.keys import PrivateKey
import datetime as dt
import basicswap.protocols.atomic_swap_1 as atomic_swap_1

class PrevOutInfo(TypedDict):
    outid: str
    amount: float  # NAV coins from decodeblsctrawtransaction
    gamma: str

class PrevOutInfoWithSpendingKey(PrevOutInfo):
    spending_key: str

class NAVInterface(BTCInterface):
    # [coin_type]
    # Side: Both
    # Call Graph: various -> coin_type
    @staticmethod
    def coin_type() -> Coins: # type: ignore[override]
        return Coins.NAV

    # [_buildHtlcImportPayload]
    # Side: Both
    # Call Graph: importItxAndSendPayloadMsgToBidder | createParticipateTxn -> _buildHtlcImportPayload
    @staticmethod
    def _buildHtlcImportPayload(msg_type, bid_id, lock_value, nav_addr_refund, chain_height):
        # blinding_key, nav_addr_redeem (address_a) and tx_data_funded are omitted:
        # the receiver derives the blinding key via ECDH, holds its own redeem
        # address in bid.nav_redeem_addr, and reconstructs the spend prevout from
        # the on-chain output (outid + bid amount) with wallet gamma recovery.
        addr_b_bytes = nav_addr_refund.encode()
        return (
            format(int(msg_type), "02x")
            + bid_id.hex()
            + lock_value.to_bytes(4, "big").hex()
            + format(len(addr_b_bytes), "02x")
            + addr_b_bytes.hex()
            + chain_height.to_bytes(4, "big").hex()
        )

    # [_buildImportBlsctScriptParams]
    # Side: Both
    # Call Graph: importItxAndSendPayloadMsgToBidder | createParticipateTxn | importItxAndRescanChain | importPtxAndApplyToBid -> _buildImportBlsctScriptParams
    @staticmethod
    def _buildImportBlsctScriptParams(nav_addr_redeem, nav_addr_refund, secret_hash, lock_value, blinding_key):
        return {
            "type": "atomic_swap",
            "address_a": nav_addr_redeem,
            "address_b": nav_addr_refund,
            "hash": secret_hash.hex(),
            "locktime": lock_value,
            "timelock_opcode": "cltv",
            "blinding_key": f"{blinding_key:064x}",
        }

    # [acceptNavInitiate]
    # Side: Offerer
    # Call Graph: acceptBid (coin_from == NAV) -> acceptNavInitiate
    def acceptNavInitiate(
        self, bid_id, bid, offer, script, secret_hash, lock_value, bid_date, cursor
    ) -> bytes:
        (
            txn,
            lock_tx_vout,
            nav_addr_redeem,
            nav_addr_refund,
            blinding_key,
        ) = self.createInitiateTxn(bid_id, bid, lock_value, secret_hash, bid_date, cursor)

        # Store the signed refund txn in case wallet is locked when refund is possible
        refund_txn = self._sc.createRefundTxn(
            Coins.NAV,
            txn,
            offer,
            bid,
            script,
            addr_refund_out=nav_addr_refund,
            cursor=cursor,
            secret_hash=secret_hash,
        )
        bid.initiate_txn_refund = bytes.fromhex(refund_txn)

        txn_funded = txn
        txn = self.signBlsct(txn)
        chain_height_before_submit = self.getChainHeight()

        txid = self.publishTx(bytes.fromhex(txn))
        self._sc.log.debug(
            f"Submitted initiate txn {self._sc.logIDT(txid)} to {self.coin_name()} chain for bid {self._sc.log.id(bid_id)}",
        )

        self.importItxAndSendPayloadMsgToBidder(
            bid_id,
            bid,
            offer,
            nav_addr_redeem,
            nav_addr_refund,
            secret_hash,
            lock_value,
            blinding_key,
            chain_height_before_submit,
            cursor,
        )

        bid.initiate_tx = SwapTx(
            bid_id=bid_id,
            tx_type=TxTypes.ITX,
            txid=bytes.fromhex(txid),
            vout=lock_tx_vout,
            tx_data=bytes.fromhex(txn),
            tx_data_funded=bytes.fromhex(txn_funded),
            script=self.createFakeNonNavHTLCScript(secret_hash, lock_value),
        )
        bid.setITxState(TxStates.TX_SENT)
        self._sc.logEvent(
            Concepts.BID,
            bid.bid_id,
            EventLogTypes.ITX_PUBLISHED,
            "",
            cursor,
        )
        return txid

    # [createRedeemTxn]
    # Side: Both
    # Call Graph: Bidder: checkQueuedActions[REDEEM_ITX] -> redeemITx -> createRedeemTxn | Offerer: checkBidState[SWAP_INITIATED] -> participateTxnConfirmed -> createRedeemTxn
    def buildNavRedeemPrevout(self, bid, nav_txn, privkey, is_ptx) -> dict:
        # Reconstruct the spend prevout without the funded tx: outid is the detected
        # on-chain output id (stored as nav_txn.txid), amount comes from the bid, and
        # gamma is recovered by the wallet at spend time (omitted here; createRedeemTxn
        # leaves it out so createblsctrawtransaction recovers it from blsctRecoveryData).
        ensure(nav_txn.txid is not None, f"NAV {'PTX' if is_ptx else 'ITX'} redeem prevout: on-chain outid not known for bid {bid.bid_id.hex()}")
        prev_amount = bid.amount_to if is_ptx else bid.amount

        ecdh_pubkey = bid.bidder_contract_pubkey if bid.was_received else bid.offerer_contract_pubkey
        blinding_key_int = self.deriveBlindingKey(privkey, ecdh_pubkey)
        return {
            "outid": nav_txn.txid.hex(),
            "amount": self.format_amount(prev_amount),
            "spending_key": self.deriveSpendingKey(
                f"{blinding_key_int:064x}", bid.nav_redeem_addr
            ),
        }

    # [createRefundTxn]
    # Side: Both
    # Call Graph: Bidder: createParticipateTxn -> createRefundTxn | Offerer: acceptBid -> createRefundTxn
    def buildNavRefundPrevout(self, bid, txn, secret_hash, addr_refund_out) -> dict:
        # Decodes funded tx via decodeblsctrawtransaction, finds the HTLC output matching secret_hash,
        # returns {"outid", "amount", "gamma"}. No spending_key — caller must derive and set it.
        prevout = self.getPrevOutInfoFromOffChainTxn(txn, secret_hash)

        bid_date = dt.datetime.fromtimestamp(bid.created_at).date()
        local_privkey = self._sc.getContractPrivkey(bid_date, bid.contract_count)
        ecdh_cpty_pubkey = bid.bidder_contract_pubkey if bid.was_received else bid.offerer_contract_pubkey
        blinding_key_int = self.deriveBlindingKey(local_privkey, ecdh_cpty_pubkey)
        prevout["spending_key"] = self.deriveSpendingKey(
            f"{blinding_key_int:064x}", addr_refund_out
        )
        return prevout

    # [checkExpectedSeed]
    # Side: Both
    # Call Graph: checkWalletSeed -> checkExpectedSeed
    def checkExpectedSeed(self, expect_seedid: str) -> bool:
        RPC_WALLET_BLANK = -37
        try:
            actual_seedid = self.getWalletSeedID()
        except Exception as e:
            if str(RPC_WALLET_BLANK) in str(e):
                return False
            raise
        return expect_seedid == actual_seedid

    # [checkCoinsReady]
    # Side: Both
    # Call Graph: Bidder: postBid -> checkCoinsReady | Offerer: acceptBid -> checkCoinsReady
    def confirmWalletMinimumBalance(self) -> None:
        try:
            fee_rate, _ = self.get_fee_rate()
            min_bal = (fee_rate * self.getHTLCSpendTxVSize()) / 1000 * 1.3
            balance = self.getWalletInfo().get("balance", 0.0)
            if balance < min_bal:
                raise ValueError(
                    f"Navio wallet balance ({balance:.8f} NAV) too low to pay redeem fees. "
                    f"Minimum {min_bal:.8f} NAV required."
                )
        except ValueError:
            raise
        except Exception as e:
            self._sc.log.warning(f"could not check NAV balance: {e}")

    # [createFakeNonNavHTLCScript]
    # Side: Both
    # Call Graph: acceptBid | createParticipateTxn | importItxAndRescanChain | importPtxAndApplyToBid -> createFakeNonNavHTLCScript
    def createFakeNonNavHTLCScript(self, secret_hash: bytearray, lock_value: int) -> bytearray:
        """
        Create a non-NAV HTLC script with zeroed-out fields,
        excluding the secret hash and lock_value.
        """
        padded_secret_hash = secret_hash.rjust(32, b'\x00')
        lock_value_bytes = lock_value.to_bytes(max(1, (lock_value.bit_length() + 7) // 8), byteorder='little')
        fake_script = (
            b'\x00' * 7 +
            padded_secret_hash +
            b'\x00' * 25 +
            bytes([len(lock_value_bytes)]) +
            lock_value_bytes
        )
        return bytearray(fake_script)

    # [createFundedHTLCTxn]
    # Side: Both
    # Call Graph: createInitiateTxn (ITX) | createParticipateTxn (PTX) -> createFundedHTLCTxn
    def createFundedHTLCTxn(
        self,
        address_a: str,
        address_b: str,
        hash: bytes,
        locktime: int,
        blinding_key: int,
        amount: int,
    ) -> tuple[str, int]:
        param: dict[str, Any] = {
            "amount": amount,
            "address_a": address_a,
            "address_b": address_b,
            "blinding_key": f"{blinding_key:064x}",
            "hash": hash.hex(),
            "locktime": locktime,
            "timelock_opcode": "cltv",
            "type": "atomic_swap",
        }
        params = [param]
        txn = self.rpc("createblsctrawtransaction", [[], params])

        txn_funded = self.rpc_wallet("fundblsctrawtransaction", [txn, None, True])
        txjs = self.rpc_wallet("decodeblsctrawtransaction", [txn_funded])

        vout_index = None
        for index, output in enumerate(txjs["outputs"]):
            if self._isHTLCScript(output["scriptPubKey"]):
                vout_index = index
                break
        if vout_index is None:
            raise ValueError(f"Failed to find vout with HTLC script")
        self._log.info(f"vout index is {vout_index}")

        return txn_funded, vout_index

    # [acceptBid]
    # Side: Offerer
    # Call Graph: checkQueuedActions[ACCEPT_BID] -> acceptBid
    def createInitiateTxn(self, bid_id, bid, locktime, secret_hash, bid_date, use_cursor):
        ensure(bid.nav_redeem_addr is not None, "NAV ITX redeem address not set; bidder must send nav_redeem_addr in BID")
        nav_addr_redeem = bid.nav_redeem_addr
        nav_addr_refund = self._sc.getReceiveAddressFromPool(Coins.NAV, bid_id, TxTypes.ITX_REFUND, use_cursor)
        seller_privkey = self._sc.getContractPrivkey(bid_date, bid.contract_count)
        blinding_key = self.deriveBlindingKey(seller_privkey, bid.bidder_contract_pubkey)

        txn, lock_tx_vout = self.createFundedHTLCTxn(
            nav_addr_redeem, nav_addr_refund, secret_hash, locktime, blinding_key, bid.amount,
        )

        return txn, lock_tx_vout, nav_addr_redeem, nav_addr_refund, blinding_key

    # [_createRawFundedTransaction]
    # Side: Both
    # Call Graph: createRawSignedTransaction -> _createRawFundedTransaction
    def _createRawFundedTransaction(
        self,
        addr_to: str,
        amount: int, # amount in navoshis
        script: Optional[bytearray] = None,
        sub_fee: bool = False,
        lock_unspents: bool = True,
    ) -> str:
        del sub_fee
        del lock_unspents

        param: dict[str, Any] = {
            "address": addr_to,
            "amount": amount,
        }
        if script is not None:
            param["script"] = bytes(script).hex()
        params = [param]

        txn = self.rpc("createblsctrawtransaction", [[], params])

        txn_funded = self.rpc_wallet("fundblsctrawtransaction", [txn, None, True])
        return txn_funded

    # [createNavRedeemTxn]
    # Side: Both
    # Call Graph: checkBidState -> createRedeemTxn (NAV early-return) -> createNavRedeemTxn
    def createNavRedeemTxn(
        self,
        bid,
        for_txn_type: str = "participate",
        addr_redeem_out=None,
        fee_rate=None,
        cursor=None,
    ) -> str:
        self._sc.log.debug(f"createNavRedeemTxn for bid {self._sc.log.id(bid.bid_id)}")

        if for_txn_type == "participate":
            nav_txn = bid.participate_tx
            is_ptx = True
            prev_amount = bid.amount_to
        else:
            nav_txn = bid.initiate_tx
            is_ptx = False
            prev_amount = bid.amount

        bid_date = dt.datetime.fromtimestamp(bid.created_at).date()
        privkey = self._sc.getContractPrivkey(bid_date, bid.contract_count)
        prevout = self.buildNavRedeemPrevout(bid, nav_txn, privkey, is_ptx)

        secret = bid.recovered_secret
        if secret is None:
            secret = self._sc.getContractSecret(bid_date, bid.contract_count)
        ensure(len(secret) == 32, "Bad secret length")

        if self._sc.coin_clients[Coins.NAV]["connection_type"] not in (
            "rpc",
            "electrum",
        ):
            return None

        if fee_rate is None:
            fee_rate, fee_src = self._sc.getFeeRateForCoin(Coins.NAV)

        tx_vsize = self.getHTLCSpendTxVSize()
        tx_fee = (fee_rate * tx_vsize) / 1000
        self._sc.log.debug(
            f"Redeem tx fee {self.format_amount(tx_fee, conv_int=True, r=1)}, rate {fee_rate}"
        )

        amount_out = prev_amount - self.make_int(tx_fee, r=1)
        ensure(amount_out > 0, "Amount out <= 0")

        if addr_redeem_out is None:
            addr_redeem_out = self._sc.getReceiveAddressFromPool(
                Coins.NAV,
                bid.bid_id,
                (
                    TxTypes.PTX_REDEEM
                    if for_txn_type == "participate"
                    else TxTypes.ITX_REDEEM
                ),
                cursor,
            )
        assert addr_redeem_out is not None
        self._sc.log.debug(f"addr_redeem_out {addr_redeem_out}")

        # NAV redeem scriptSig pushes the secret then OP_1
        redeem_script = b"\x20" + secret + b"\x51"
        redeem_txn = self.createRedeemTxn(
            prevout, addr_redeem_out, amount_out, redeem_script
        )
        # signBlsct validates internally; NAV prevout fields (outid, spending_key)
        # are incompatible with verifyRawTransaction
        redeem_txn = self.signBlsct(redeem_txn)

        if self._sc.debug and self.get_connection_type() == "rpc":
            redeem_txjs = self.rpc("decoderawtransaction", [redeem_txn])
            prev_outid = (redeem_txjs.get("vin") or [{}])[0].get("outid")
            redeem_outid = (redeem_txjs.get("vout") or [{}])[0].get("hash")
            if prev_outid and redeem_outid:
                self._sc.log.debug(
                    f"Have valid redeem tx {self._sc.log.id(redeem_outid)} for contract {for_txn_type} tx {self._sc.log.id(prev_outid)}"
                )

        return redeem_txn

    # [createNavRefundTxn]
    # Side: Both
    # Call Graph: acceptBid / createParticipateTxn -> createRefundTxn (NAV early-return) -> createNavRefundTxn
    def createNavRefundTxn(
        self,
        txn,
        offer,
        bid,
        txn_script: bytearray,
        addr_refund_out=None,
        tx_type=TxTypes.ITX_REFUND,
        cursor=None,
        secret_hash: bytes | None = None,
    ) -> str:
        self._sc.log.debug(f"createNavRefundTxn for bid {self._sc.log.id(bid.bid_id)}")

        prevout = self.buildNavRefundPrevout(bid, txn, secret_hash, addr_refund_out)

        lock_value = DeserialiseNum(txn_script, 64)
        sequence: int = 1
        if offer.lock_type < TxLockTypes.ABS_LOCK_BLOCKS:
            sequence = lock_value

        fee_rate, fee_src = self._sc.getFeeRateForCoin(Coins.NAV)
        tx_vsize = self.getHTLCSpendTxVSize(False)
        tx_fee = (fee_rate * tx_vsize) / 1000
        self._sc.log.debug(
            f"Refund tx fee {self.format_amount(tx_fee, conv_int=True, r=1)}, rate {fee_rate}"
        )

        amount_out = self.make_int(prevout["amount"], r=1) - self.make_int(tx_fee, r=1)
        if amount_out <= 0:
            raise ValueError("Refund amount out <= 0")

        if addr_refund_out is None:
            addr_refund_out = self._sc.getReceiveAddressFromPool(
                Coins.NAV, bid.bid_id, tx_type, cursor
            )
        ensure(addr_refund_out is not None, "addr_refund_out is null")
        self._sc.log.debug(f"addr_refund_out {addr_refund_out}")

        locktime: int = 0
        if offer.lock_type in (
            TxLockTypes.ABS_LOCK_BLOCKS,
            TxLockTypes.ABS_LOCK_TIME,
        ):
            locktime = lock_value

        refund_txn = self.createRefundTxn(
            prevout, addr_refund_out, amount_out, locktime, sequence, txn_script
        )
        # signBlsct validates internally; NAV prevout fields (outid, spending_key)
        # are incompatible with verifyRawTransaction
        refund_txn = self.signBlsct(refund_txn)

        if self._sc.debug and self.get_connection_type() == "rpc":
            refund_txjs = self.rpc("decoderawtransaction", [refund_txn])
            prev_outid = (refund_txjs.get("vin") or [{}])[0].get("outid")
            refund_outid = (refund_txjs.get("vout") or [{}])[0].get("hash")
            if prev_outid and refund_outid:
                self._sc.log.debug(
                    f"Have valid refund tx {self._sc.log.id(refund_outid)} for contract tx {self._sc.log.id(prev_outid)}"
                )

        return refund_txn

    # [createParticipateTxn]
    # Side: Bidder
    # Call Graph: update -> checkBidState[BID_ACCEPTED] -> initiateTxnConfirmed -> createParticipateTxn
    def createParticipateTxn(self, bid_id, bid, offer) -> tuple:
        # Extract secret hash from ITX script and use offerer's nav address as redeem address and bidder's nav address as refund address
        secret_hash = atomic_swap_1.extractScriptSecretHash(bid.initiate_tx.script)
        nav_addr_redeem = bid.nav_redeem_addr
        ensure(nav_addr_redeem is not None, "NAV redeem address not set; server must send nav_redeem_addr in BID_ACCEPT")
        nav_addr_refund = self._sc.getReceiveAddressFromPool(Coins.NAV, bid_id, TxTypes.PTX_REFUND, None)

        # Derive blinding key via ECDH (bidder_privkey, offerer_pubkey)
        bid_date = dt.datetime.fromtimestamp(bid.created_at).date()
        bidder_privkey = self._sc.getContractPrivkey(bid_date, bid.contract_count)
        lock_value = self.getParticipateLockValue(offer)
        blinding_key = self.deriveBlindingKey(bidder_privkey, bid.offerer_contract_pubkey)
        # Create funded PTX and PTX refund txn
        txn_funded, vout_index = self.createFundedHTLCTxn(
            nav_addr_redeem, nav_addr_refund, secret_hash, lock_value, blinding_key, bid.amount_to,
        )
        participate_script = self.createFakeNonNavHTLCScript(secret_hash, lock_value)
        refund_txn = self._sc.createRefundTxn(
            Coins.NAV, txn_funded, offer, bid, participate_script,
            addr_refund_out=nav_addr_refund, secret_hash=secret_hash, tx_type=TxTypes.PTX_REFUND,
        )
        bid.participate_txn_refund = bytes.fromhex(refund_txn)

        # Sign PTX and get the txid
        txn_signed = self.signBlsct(txn_funded)
        txjs = self.rpc("decoderawtransaction", [txn_signed])
        txid = txjs["txid"]

        # Import HTLC script so wallet tracks the PTX output
        params = self._buildImportBlsctScriptParams(
            nav_addr_redeem,
            nav_addr_refund,
            secret_hash,
            lock_value,
            blinding_key,
        )
        self.importBlsctScript(params, None)

        # Build NAV_PTX_IMPORT payload to send to offerer
        chain_height = self.getChainHeight()
        nav_ptx_import_payload = self._buildHtlcImportPayload(
            MessageTypes.NAV_PTX_IMPORT, bid_id, lock_value,
            nav_addr_refund, chain_height,
        )

        # Update bid participate_tx fields
        self._sc.addParticipateTxn(bid_id, bid, Coins.NAV, txid, vout_index, chain_height)
        bid.participate_tx.script = participate_script
        bid.participate_tx.tx_data = bytes.fromhex(txn_signed)
        bid.participate_tx.tx_data_funded = bytes.fromhex(txn_funded)
        prevout_info = self.getPrevOutInfoFromOffChainTxn(txn_funded, secret_hash)
        bid.participate_tx.txid = bytes.fromhex(prevout_info["outid"])

        return txn_signed, nav_ptx_import_payload

    # [createRawFundedTransaction]
    # Side: Both
    # Call Graph: fund helper for non-HTLC NAV txns
    def createRawFundedTransaction(
        self,
        addr_to: str,
        amount: int,
        sub_fee: bool = False,
        lock_unspents: bool = True,
    ) -> str:
        return self._createRawFundedTransaction(
            addr_to,
            amount,
            None,
            sub_fee,
            lock_unspents)

    # [createRawSignedTransaction]
    # Side: Both
    # Call Graph: createInitiateTxn | createParticipateTxn (non-NAV path) -> createRawSignedTransaction
    def createRawSignedTransaction(self, addr_to, amount) -> str:
        txn_funded = self._createRawFundedTransaction(addr_to, amount)
        return self.rpc_wallet("signblsctrawtransaction", [txn_funded])

    # [createRedeemTxn]
    # Side: Both
    # Call Graph: Bidder: redeemITx -> createRedeemTxn | Offerer: participateTxnConfirmed -> createRedeemTxn
    def createRedeemTxn(
        self,
        prevout: PrevOutInfoWithSpendingKey, # amount is in NAV
        output_addr: str,
        output_value: int, # in Navoshis
        txn_script: bytes | None = None,
    ) -> str:
        # gamma omitted: createblsctrawtransaction recovers it from the wallet's
        # blsctRecoveryData (populated when the HTLC script was imported + rescanned).
        in_params: dict[str, Any] = {
            "outid": prevout["outid"],
            "value": self.make_int(prevout["amount"]),  # NAV to Navoshis
            "spending_key": prevout["spending_key"],
            "scriptSig": txn_script.hex(),
        }
        out_params: dict[str, Any] = {
            "amount": output_value,  # amount is in Navoshis
            "address": output_addr,
        }
        params = [[in_params], [out_params]]
        txn = self.rpc("createblsctrawtransaction", params)

        fee = self.make_int(prevout["amount"], r=1) - output_value
        try:
            txn_funded = self.rpc_wallet("fundblsctrawtransaction", [txn, None, False, fee])
        except Exception as e:
            if "Insufficient funds" in str(e):
                raise TemporaryError(str(e))
            raise

        return txn_funded

    # [createRefundTxn]
    # Side: Both
    # Call Graph: Bidder: createParticipateTxn -> createRefundTxn | Offerer: acceptBid -> createRefundTxn
    def createRefundTxn(
        self,
        prevout: PrevOutInfoWithSpendingKey, # amount is in NAV
        output_addr: str,
        output_value: int, # in Navoshis
        locktime: int,
        sequence: int,
        txn_script: bytes | None = None,
    ) -> str:
        del txn_script
        # For ABS lock types, locktime holds the CLTV value; for SEQUENCE types, sequence does.
        nav_locktime = locktime if locktime != 0 else sequence

        in_params: dict[str, Any] = {
            "outid": prevout["outid"],
            "value": self.make_int(prevout["amount"]),  # NAV to Navoshis
            "gamma": prevout["gamma"],
            "spending_key": prevout["spending_key"],
            "scriptSig": "00", # select else path
            "sequence": nav_locktime, # CLTV requires nSequence == script locktime
        }
        out_params: dict[str, Any] = {
            "amount": output_value,  # amount is in Navoshis
            "address": output_addr,
        }
        params = [[in_params], [out_params]]
        txn = self.rpc("createblsctrawtransaction", params)

        fee = self.make_int(prevout["amount"], r=1) - output_value
        txn_funded = self.rpc_wallet("fundblsctrawtransaction", [txn, None, False, fee])

        return txn_funded

    # [getContractPrivkey]
    # Side: Both
    # Call Graph: various -> getContractPrivkey
    def deriveBLSKey(self, evkey, key_path_base) -> bytes:
        BLS_GROUP_ORDER = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001
        parent_path = key_path_base.rpartition("/")[0]
        # TODO NAV: use 1 upon creating a pr
        nonce = 2
        while True:
            key_path = "{}/{}".format(parent_path, nonce)
            extkey = self._sc.callcoinrpc(Coins.PART, "extkey", ["info", evkey, key_path])["key_info"]["result"]
            privkey = decodeWif(
                self._sc.callcoinrpc(Coins.PART, "extkey", ["info", extkey])["key_info"]["privkey"]
            )
            i = b2i(privkey) % BLS_GROUP_ORDER
            if i != 0:
                return i.to_bytes(32, "big")
            nonce += 1
            if nonce > 0x7FFFFFFF:
                raise ValueError("deriveBLSKey failed")

    # [deriveBlindingKey]
    # Side: Both
    # Call Graph: buildNavRedeemPrevout | buildNavRefundPrevout | createInitiateTxn | createParticipateTxn -> deriveBlindingKey
    def deriveBlindingKey(self, privkey: bytes, pubkey: bytes) -> int:
        """Derive a blinding key via ECDH: SHA256(ECDH(privkey, pubkey))."""

        ecdh_secret = PrivateKey(privkey).ecdh(pubkey)
        blinding_key_bytes = sha256(ecdh_secret)
        return int.from_bytes(blinding_key_bytes, "big")

    # [deriveSpendingKey]
    # Side: Both
    # Call Graph: buildNavRedeemPrevout | buildNavRefundPrevout -> deriveSpendingKey
    def deriveSpendingKey(self, blinding_key_hex: str, address: str) -> str:
        """Derive the private spending key for a BLSCT HTLC output.
        Uses rpc_wallet because the address must be owned by this wallet."""
        return self.rpc_wallet("deriveblsctspendingkey", [blinding_key_hex, address])

    # [describeTx]
    # Side: Both
    # Call Graph: createInitiateTxn (non-NAV path) -> describeTx
    def describeTx(self, tx_hex: str):
        # tx_hex is expected to be sigined
        # for txs before signing, use decodeblsctrawtransaction
        return self.rpc("decoderawtransaction", [tx_hex])

    # [checkBidState / SWAP_INITIATED]
    # Side: Bidder
    # Call Graph: update -> checkBidState[SWAP_INITIATED]
    def detectNavItxRefund(self, bid) -> bool:
        # NAV ITX may be refunded while waiting for PTX confirmation.
        # BLSCT outputs have no visible address, so check via isHTLCTxnSpent (listblsctunspent).
        if (
            bid.initiate_tx is not None
            and bid.getITxState() in (TxStates.TX_SENT, TxStates.TX_CONFIRMED)
            and self.isHTLCTxnSpent(bid.initiate_tx.script)
        ):
            self._sc.log.info(f"NAV ITx spent (refunded) in SWAP_INITIATED for bid {self._sc.log.id(bid.bid_id)}, marking TX_REFUNDED")
            bid.setITxState(TxStates.TX_REFUNDED)
            return True
        return False

    # [extractHTLCLockVal]
    # Side: Both
    # Call Graph: processBidAccept | isInitiateTxnOnChain | tryToGetNavPtxInfoFromChain | getNavLockTxHeight | isHTLCTxnSpent -> extractHTLCLockVal
    def extractHTLCLockVal(self, script: bytes, is_nav: bool) -> int:
        if is_nav:
            push_size = script[90]
            locktime_bytes = script[91:91 + push_size]
        else:
            push_size = script[64]
            locktime_bytes = script[65:65 + push_size]
        return int.from_bytes(locktime_bytes, byteorder='little')

    # Workaround: naviod crashes with getblock verbosity=2 (MoneyRange assertion). Remove once naviod fixes.
    # [getBlockWithTxns]
    # Side: Both
    # Call Graph: checkForSpends -> getBlockWithTxns
    def getBlockWithTxns(self, block_hash: str):
        # naviod crashes with getblock with verbosity 2 (MoneyRange bug),
        # so use getblockheader and return an empty tx list b/c NAV will not use txs there
        header = self.rpc("getblockheader", [block_hash])
        return {
            "hash": header["hash"],
            "previousblockhash": header.get("previousblockhash", ""),
            "time": header["time"],
            "height": header["height"],
            "tx": [],
        }

    # [get_fee_rate]
    # Side: Both
    # Call Graph: getFeeRateForCoin | confirmWalletMinimumBalance -> get_fee_rate
    def get_fee_rate(self, conf_target: int = 2) -> tuple[float, str]:
        del conf_target
        chain_client_settings = self._sc.getChainClientSettings(
            self.coin_type()
        )  # basicswap.json
        override_feerate = chain_client_settings.get("override_feerate", None)
        if override_feerate:
            self._log.debug(
                f"Fee rate override used for {self.coin_name()}: {override_feerate}"
            )
            return override_feerate, "override_feerate"

        navoshi_per_byte = 125
        navoshi_per_kb = navoshi_per_byte * 1000
        nav_per_kb = navoshi_per_kb * 1e-8

        return nav_per_kb, "default_feerate"

    # [getHTLCSpendTxVSize]
    # Side: Both
    # Call Graph: createRedeemTxn | estimateWithdrawFee | confirmWalletMinimumBalance -> getHTLCSpendTxVSize
    def getHTLCSpendTxVSize(self, redeem: bool = True) -> int:
        del redeem
        # always using the size of a refund transaction since the size
        # difference between redeem and refund transactions are small
        return 1336

    # [getNavLockTxHeight]
    # Side: Offerer
    # Call Graph: checkBidState[SWAP_INITIATED] -> isInitiateTxnOnChain | tryToGetNavPtxInfoFromChain -> getNavLockTxHeight
    def getNavLockTxHeight(
        self,
        txid,
        dest_address,
        bid_amount,
        rescan_from,
        lock_val: int = 0,
    ):
        """BLSCT-specific lock tx lookup.
        dest_address is the secret_hash hex. lock_val is the NAV CLTV lock block
        height extracted from the fake participate script, used to discriminate
        between UTxOs sharing the same secret_hash (e.g. in test environments
        where the Particl HD wallet reuses the same secret)."""
        del bid_amount, rescan_from, txid
        if not dest_address:
            return None

        secret_hash = dest_address.lower()
        try:
            utxos = self._listBlsctUnspent()
            self._log.debug(f"getNavLockTxHeight: {len(utxos)} UTxOs from listblsctunspent, seeking secret_hash={secret_hash}")
            for utxo in utxos:
                utxo_spk = utxo.get("scriptPubKey", "").lower()
                if not self._isHTLCScript(utxo_spk):
                    continue
                spk_bytes = bytes.fromhex(utxo_spk)
                spk_secret_hash = atomic_swap_1.extractScriptSecretHash(spk_bytes).hex()
                spk_lock_val = self.extractHTLCLockVal(spk_bytes, is_nav=True)
                self._log.debug(f"getNavLockTxHeight: HTLC UTxO spk_secret_hash={spk_secret_hash} spk_lock_val={spk_lock_val}")
                if spk_secret_hash == secret_hash and spk_lock_val == lock_val:
                    confirmations = utxo.get("confirmations", 0)
                    chain_info = self.rpc("getblockchaininfo")
                    chain_height = chain_info["blocks"]
                    block_height = max(0, chain_height - confirmations + 1) if confirmations > 0 else 0
                    rv = {
                        "depth": confirmations,
                        "height": block_height,
                        "outid": utxo.get("outid", None) or utxo.get("outputHash", ""),
                        "value": int(round(utxo.get("amount", 0) * 100_000_000)),
                    }
                    self._log.info(f"getNavLockTxHeight found HTLC via listblsctunspent: {rv}")
                    return rv
        except Exception as e:
            self._log.error(f"getNavLockTxHeight listblsctunspent search failed: {e}")

        return None

    # [getNewAddress]
    # Side: Both
    # Call Graph: getReceiveAddressFromPool -> getNewAddress
    def getNewAddress(self, use_segwit: bool, label: str = "swap_receive") -> str:
        del use_segwit
        address: str = self.rpc(
            "getnewaddress",
            [
                label,
                "blsct",
            ],
        )
        return address

    # [getParticipateLockValue]
    # Side: Bidder
    # Call Graph: createParticipateTxn -> getParticipateLockValue
    def getParticipateLockValue(self, offer) -> int:
        # half of ITX duration; 30s NAV block time (no lock_blocks field in add-navio-new)
        nav_blocks = offer.lock_value // 2 // 30
        return self.getChainHeight() + nav_blocks

    # [getPrevOutInfoFromOffChainTxn]
    # Side: Both
    # Call Graph: buildNavRefundPrevout | createParticipateTxn -> getPrevOutInfoFromOffChainTxn
    def getPrevOutInfoFromOffChainTxn(self, txn_hex: str, secret_hash: bytes) -> PrevOutInfo:
        txjs = self.rpc_wallet("decodeblsctrawtransaction", [txn_hex])
        self._log.debug(f"getPrevOutInfoFromOffChainTxn: secret_hash={secret_hash.hex()}")
        for output in txjs.get("outputs", []):
            spk = output.get("scriptPubKey", "")
            if not self._isHTLCScript(spk):
                continue
            spk_secret_hash = atomic_swap_1.extractScriptSecretHash(bytes.fromhex(spk))
            self._log.debug(f"found HTLC script: spk_secret_hash={spk_secret_hash.hex()}")
            if secret_hash == spk_secret_hash:
                return {
                    "outid": output["outputHash"],
                    "amount": output["amount"],
                    "gamma": output["gamma"],
                }
        raise ValueError(f"No HTLC output found for secret_hash={secret_hash.hex()}")

    # [getProofOfFunds]
    # Side: Both
    # Call Graph: postOffer | postBid -> getProofOfFunds
    def getProofOfFunds(self, amount_for, extra_commit_bytes):
        amount_btc = amount_for / 100_000_000
        additional_commitment = extra_commit_bytes.hex()
        result = self.rpc_wallet(
            "createblsctbalanceproof", [amount_btc, additional_commitment]
        )
        proof_hex = result["proof"]
        return ("blsct_balance_proof", proof_hex, [])

    # [getSeedHash]
    # Side: Both
    # Call Graph: storeSeedIDForCoin -> getSeedHash
    def getSeedHash(self, seed: bytes) -> bytes:
        return seed

    # [_isScriptRefundMature]
    # Side: Both
    # Call Graph: checkBidState -> _isScriptRefundMature -> getTxLocktime
    def getTxLocktime(self, tx_data) -> int:
        # tx_data is the initiate (HTLC) tx for NAV; the BLSCT refund tx can't be
        # deserialised by the BTC parser, so read the CLTV value from the HTLC script.
        return self.extractHTLCLockVal(tx_data.script, is_nav=False)

    # [getWalletInfo]
    # Side: Both
    # Call Graph: getWalletInfo | updateWalletInfo | confirmWalletMinimumBalance -> getWalletInfo
    def getWalletInfo(self):
        rv = super().getWalletInfo()
        # listblsctunspent returns both wallet outputs (address present) and
        # HTLC watch-only imports (no address). The base getwalletinfo balance
        # counts the imported HTLC outputs, inflating the displayed total.
        confirmed = 0.0
        unconfirmed = 0.0
        try:
            outputs = self.rpc_wallet("listblsctunspent", [0])
            for o in outputs:
                if not o.get("address"):
                    continue
                amount = float(o.get("amount", 0))
                if o.get("confirmations", 0) >= 1:
                    confirmed += amount
                else:
                    unconfirmed += amount
            rv["balance"] = round(confirmed, 8)
            rv["unconfirmed_balance"] = round(unconfirmed, 8)
        except Exception as e:
            self._log.warning(f"NAV getWalletInfo listblsctunspent failed: {e}")
        return rv

    # [getWalletSeedID]
    # Side: Both
    # Call Graph: checkWalletSeed | checkExpectedSeed -> getWalletSeedID
    def getWalletSeedID(self) -> str:
        """
        The Navio wallet has been initialized using the root key generated by
        `getWalletKey(c, 1)` as the seed.
        """
        return self.rpc("getblsctseed")

    # [checkBidState / SWAP_PARTICIPATING]
    # Side: Bidder
    # Call Graph: update -> checkBidState[SWAP_PARTICIPATING]
    def handleSwapParticipating(self, bid_id, bid, coin_from, coin_to) -> bool:
        # NAV HTLC outputs have no visible address; isHTLCTxnSpent polls via listblsctunspent.
        # coin_from == NAV: ITX is NAV — check if ITX is spent to mark it TX_REDEEMED.
        # coin_to == NAV: PTX is NAV — check if PTX is spent; distinguish refund vs redeem via PTX_REFUND_PUBLISHED event.
        save_bid = False
        if coin_from == Coins.NAV and bid.initiate_tx is not None:
            if self.isHTLCTxnSpent(bid.initiate_tx.script):
                bid.setITxState(TxStates.TX_REDEEMED)
                save_bid = True
        elif coin_to == Coins.NAV and bid.getPTxState() != TxStates.TX_REDEEMED:
            if self.isHTLCTxnSpent(bid.participate_tx.script):
                events = self._sc.getEvents(int(Concepts.BID), bid_id)
                ptx_refund_published = any(e.event_type == int(EventLogTypes.PTX_REFUND_PUBLISHED) for e in events)
                bid.setPTxState(TxStates.TX_REFUNDED if ptx_refund_published else TxStates.TX_REDEEMED)
                save_bid = True
        return save_bid

    # [importBlsctScript]
    # Side: Both
    # Call Graph: importItxAndSendPayloadMsgToBidder | createParticipateTxn | importItxAndRescanChain | importPtxAndApplyToBid -> importBlsctScript
    def importBlsctScript(self, params: dict, rescan_from: None | int) -> dict:
        if rescan_from is not None:
            try:
                chain_height = self.rpc("getblockchaininfo")["blocks"]
                rescan_from = min(rescan_from, chain_height)
            except Exception as e:
                self._log.warning(f"importBlsctScript: could not get chain height: {e}")
        rescan = rescan_from is not None
        args = [params, rescan]
        if rescan:
            args.append(rescan_from)
        return self.rpc_wallet("importblsctscript", args)

    # [processBidAccept / processNavItxImport]
    # Side: Bidder
    # Call Graph: processMsg[BID_ACCEPT] -> processBidAccept
    #             processMsg[NAV_ITX_IMPORT] -> processNavItxImport
    def importItxAndRescanChain(self, bid_id, bid) -> None:
        if bid.nav_itx_import_info is None:
            return
        _, lock_value, nav_addr_refund, rescan_from = self._parseHtlcImportMsg(bid.nav_itx_import_info)
        secret_hash = atomic_swap_1.extractScriptSecretHash(bid.initiate_tx.script)
        # blinding_key derived via ECDH; nav_addr_redeem is our own (sent in BID)
        bid_date = dt.datetime.fromtimestamp(bid.created_at).date()
        privkey = self._sc.getContractPrivkey(bid_date, bid.contract_count)
        ecdh_pubkey = bid.bidder_contract_pubkey if bid.was_received else bid.offerer_contract_pubkey
        blinding_key = self.deriveBlindingKey(privkey, ecdh_pubkey)
        nav_addr_redeem = bid.nav_redeem_addr
        params = self._buildImportBlsctScriptParams(
            nav_addr_redeem, nav_addr_refund, secret_hash, lock_value, blinding_key,
        )
        self.importBlsctScript(params, rescan_from)
        self._sc.log.info(f"Imported NAV ITX HTLC script for bid {self._sc.log.id(bid_id)}")
        # Update initiate_tx.script to fake BLSCT format (with absolute locktime) so
        # isHTLCTxnSpent can match the on-chain UTxO locktime correctly.
        bid.initiate_tx.script = self.createFakeNonNavHTLCScript(secret_hash, lock_value)
        # ITx is already on-chain when bidder imports; rescanblockchain finds the existing UTXO
        if rescan_from is not None:
            try:
                chain_height = self.rpc("getblockchaininfo")["blocks"]
                rescan_from = min(rescan_from, chain_height)
            except Exception as e:
                self._sc.log.warning(f"importItxAndRescanChain: could not clamp rescan_from: {e}")
            self._sc.log.info(f"Rescanning from height {rescan_from} to find ITX UTXO")
            self.rpc_wallet("rescanblockchain", [rescan_from])
            self._sc.log.info(f"Rescan complete")
        bid.nav_itx_import_info = None

    # [acceptBid]
    # Side: Offerer
    # Call Graph: checkQueuedActions[ACCEPT_BID] -> acceptBid
    def importItxAndSendPayloadMsgToBidder(self, bid_id, bid, offer, nav_addr_redeem, nav_addr_refund, secret_hash, lock_value, blinding_key, chain_height_before_submit, use_cursor):
        # Import HTLC script so wallet tracks the output after tx aggregation (txid changes when mined).
        params = self._buildImportBlsctScriptParams(
            nav_addr_redeem,
            nav_addr_refund,
            secret_hash,
            lock_value,
            blinding_key,
        )
        self.importBlsctScript(params, chain_height_before_submit)

        # Send NAV_ITX_IMPORT to bidder so they can import the HTLC script.
        # The bidder reconstructs the redeem prevout from the on-chain output.
        nav_itx_import_payload = self._buildHtlcImportPayload(
            MessageTypes.NAV_ITX_IMPORT, bid_id, lock_value,
            nav_addr_refund, chain_height_before_submit,
        )
        self._sc.sendMessage(
            offer.addr_from, bid.bid_addr, nav_itx_import_payload,
            self._sc.SMSG_SECONDS_IN_HOUR * 2, use_cursor,
            message_nets=bid.message_nets,
            payload_version=offer.smsg_payload_version,
        )
        self._sc.log.info(f"Sent NAV_ITX_IMPORT to bidder for bid {self._sc.log.id(bid_id)}")

    # [checkBidState / SWAP_INITIATED]
    # Side: Offerer
    # Call Graph: update -> checkBidState[SWAP_INITIATED]
    def importPtxAndApplyToBid(self, bid_id, bid) -> bool:
        if bid.nav_ptx_import_info is None:
            return False
        _, lock_value, nav_addr_refund, rescan_from = self._parseHtlcImportMsg(bid.nav_ptx_import_info)
        secret_hash = atomic_swap_1.extractScriptSecretHash(bid.initiate_tx.script)
        # blinding_key derived via ECDH; nav_addr_redeem is our own (sent in BID_ACCEPT)
        bid_date = dt.datetime.fromtimestamp(bid.created_at).date()
        privkey = self._sc.getContractPrivkey(bid_date, bid.contract_count)
        ecdh_pubkey = bid.bidder_contract_pubkey if bid.was_received else bid.offerer_contract_pubkey
        blinding_key = self.deriveBlindingKey(privkey, ecdh_pubkey)
        nav_addr_redeem = bid.nav_redeem_addr
        params = self._buildImportBlsctScriptParams(
            nav_addr_redeem, nav_addr_refund, secret_hash, lock_value, blinding_key,
        )
        self.importBlsctScript(params, rescan_from)
        self._sc.log.info(f"Imported NAV PTX HTLC script for bid {self._sc.log.id(bid_id)}")
        fake_script = self.createFakeNonNavHTLCScript(secret_hash, lock_value)
        bid.participate_tx.script = fake_script
        bid.nav_ptx_import_info = None
        return True

    # [initialiseWallet]
    # Side: Both
    # Call Graph: initialiseWallet (wallet setup) -> initialiseWallet
    def initialiseWallet(self, key_bytes, restore_time: int = -1):
        del restore_time
        key_wif = self.encodeKey(key_bytes)
        try:
            self.rpc_wallet("setblsctseed", [key_wif])
        except Exception as e:
             if "Already have this key" in str(e):
                 self._log.info(f"The same seed ({key_wif}) has already been set...")
             else:
                 self._log.debug(f"setblsctseed failed: {e}")
                 raise (e)

    # [_isHTLCScript]
    # Side: Both
    # Call Graph: createFundedHTLCTxn | getNavLockTxHeight | isHTLCTxnSpent -> _isHTLCScript
    def _isHTLCScript(self, script: str) -> bool:
        """
        Determines if a script is a Navio HTLC script.

        OP_IF
            OP_SIZE
            32
            OP_EQUALVERIFY
            OP_SHA256
            <32-byte secret hash>
            OP_EQUALVERIFY
            <48-byte address_a>
        OP_ELSE
            <1-4 byte locktime>
            OP_CHECKLOCKTIMEVERIFY
            OP_DROP
            <48-byte address_b>
        OP_ENDIF
        OP_BLSCHECKSIG

        >>> hex = "6382012088a820b812e53d1bd15a928803df44ab86c6a286d9a3d6625a3738f"
        >>> hex += "bed32d89a4c7c178830a7b9a59a0e305eef4f756909e6fa107091fc6d2b2743"
        >>> hex += "3d110d5d3c95ff987a0182bbd2e19897ee71af0466006cc2755467042c688b6"
        >>> hex += "9b17530a7b9a59a0e305eef4f756909e6fa107091fc6d2b27433d110d5d3c95"
        >>> hex += "ff987a0182bbd2e19897ee71af0466006cc2755468b3"
        >>> nav = NAVInterface()
        >>> nav._isHTLCScript(hex)
        True
        >>> hex = "6382012088a8206756e66c48945a6851790e94fed56b86ec9d1e05116d4d289bf"
        >>> hex += "62f858389c3998830a6c43cded614e403d715cd7f28a57736214937dd811bd7e2927eed4cd"
        >>> hex += "904ee8df0066923c7dc021a36e94fa6f8fa21e36703710040b17530a769dfbee940c4f72c1"
        >>> hex += "29b5a315822dabda7932f5f12b8d1c56d2335544995504af3e11446a3b544cb6ec51403377"
        >>> hex += "33468b3"
        >>> nav._isHTLCScript(hex)
        True
        >>> nav._isHTLCScript("76a91488ac")
        False
        """
        script = script.lower()
        pos = 0

        def consume(exp: str) -> bool:
            nonlocal pos
            if pos + len(exp) > len(script):
                return False
            if script[pos:pos + len(exp)] == exp:
                pos += len(exp)
                return True
            else:
                return False

        def skip(n: int) -> bool:
            nonlocal pos
            pos = pos + n*2
            return pos <= len(script)

        def consume_locktime() -> bool:
            nonlocal pos
            push_size = int(script[pos:pos + 2], 16)
            return skip(push_size + 1)

        def consume_timelock_op() -> bool:
            nonlocal pos
            if pos + 2 > len(script):
                return False
            if script[pos:pos + 2] in ("b1", "b2"):
                pos += 2
                return True
            return False

        def all_consumed() -> bool:
            return pos == len(script)

        return (
            # 63 (OP_IF)
            # 82 (OP_SIZE)
            # 01 20 (32 bytes)
            # 88 (OP_EQUALVERIFY)
            # a8 (OP_SHA256)
            # 20 (Data Length 32)
            consume("6382012088a820") and
            # secret hash
            skip(32) and
            # 88 (OP_EQUALVERIFY)
            # 30 (Data Length 48)
            consume("8830") and
            # address_a
            skip(48) and
            # 67 (OP_ELSE)
            consume("67") and
            # 1-4 byte locktime
            consume_locktime() and
            # b1 (OP_CHECKLOCKTIMEVERIFY) or b2 (OP_CHECKSEQUENCEVERIFY)
            # 75 (OP_DROP)
            # 30 (Data Length 48)
            consume_timelock_op() and consume("7530") and
            # address_b
            skip(48) and
            # 68 (OP_ENDIF)
            # b3 (OP_BLSCHECKSIG)
            consume("68b3") and
            # should have read everything
            all_consumed()
        )

    # [isHTLCTxnSpent]
    # Side: Both
    # Call Graph: detectNavItxRefund | isNavItxRefunded | handleSwapParticipating -> isHTLCTxnSpent
    def isHTLCTxnSpent(self, script: bytes) -> bool:
        secret_hash = atomic_swap_1.extractScriptSecretHash(script)
        locktime = self.extractHTLCLockVal(script, is_nav=False)
        self._log.debug(f"isHTLCTxnSpent: secret_hash={secret_hash.hex()} {locktime=} script={script.hex()}")
        try:
            utxos = self._listBlsctUnspent()
            for utxo in utxos:
                spk = utxo.get("scriptPubKey", "")
                if not self._isHTLCScript(spk):
                    continue
                spk_bytes = bytes.fromhex(spk)
                spk_secret_hash = atomic_swap_1.extractScriptSecretHash(spk_bytes)
                spk_lock_val = self.extractHTLCLockVal(spk_bytes, is_nav=True)
                if secret_hash == spk_secret_hash and locktime == spk_lock_val:
                    # UTxO appears in wallet — verify it's still in the confirmed UTXO set.
                    # listblsctunspent on watchonly wallets does not remove a UTxO when it
                    # is spent by an external wallet.  gettxout queries the consensus UTXO
                    # set directly (wallet-independent, mempool-independent) and returns an
                    # empty result once the output is confirmed-spent.
                    outid = utxo.get("outid")
                    if outid:
                        result = self.rpc("gettxout", [outid])
                        if result:
                            # Still in consensus UTXO set → genuinely unspent
                            self._log.debug(f"isHTLCTxnSpent: outid={outid[:16]}... in UTXO set (unspent)")
                            return False
                        else:
                            # Empty result → confirmed spent
                            self._log.debug(f"isHTLCTxnSpent: outid={outid[:16]}... not in UTXO set (spent)")
                            return True
                    # No outid available — fall back to listblsctunspent result
                    self._log.debug(f"isHTLCTxnSpent: found matching utxo, not spent yet: {utxo=}")
                    return False
            self._log.debug(f"isHTLCTxnSpent: {secret_hash.hex()} is spent")
            return True

        except Exception as e:
            self._log.error(f"Failed to check if HTLC txn is spent: {e}")
        return False

    # [checkBidState]
    # Side: Offerer
    # Call Graph: update -> checkBidState
    def isInitiateTxnOnChain(self, bid) -> dict:
        # Search by secret hash via listblsctunspent; BLSCT outputs have no visible address
        secret_hash = atomic_swap_1.extractScriptSecretHash(bid.initiate_tx.script)
        locktime = self.extractHTLCLockVal(bid.initiate_tx.script, is_nav=False)
        return self.getNavLockTxHeight(
            bid.initiate_tx.txid,
            secret_hash.hex(),
            bid.amount,
            bid.chain_a_height_start,
            lock_val=locktime,
        )

    # [checkBidState]
    # Side: Offerer
    # Call Graph: update -> checkBidState
    def isNavItxRefunded(self, bid) -> bool:
        # ITX was previously confirmed but UTXO gone — spent before re-detection, likely refunded
        if (
            bid.getITxState() == TxStates.TX_SENT
            and bid.initiate_tx.conf is not None
            and bid.initiate_tx.conf >= 1
            and self.isHTLCTxnSpent(bid.initiate_tx.script)
        ):
            bid.setITxState(TxStates.TX_REFUNDED)
            bid.setState(BidStates.SWAP_COMPLETED)
            self._sc.saveBid(bid.bid_id, bid)
            return True
        return False

    # [isTxNonFinalError]
    # Side: Both
    # Call Graph: acceptBid | checkBidState -> isTxNonFinalError
    def isTxNonFinalError(self, err_str: str) -> bool:
        # non-final-input: refund submitted before CLTV locktime expires
        # bad-inputs-unknown: refund input not in UTXO set; PTX still in mempool (BLSCT outputs unspendable until confirmed)
        return "non-final-input" in err_str or "bad-input-unknown" in err_str or "bad-inputs-unknown" in err_str or "'code': 25" in err_str

    # [_listBlsctUnspent]
    # Side: Both
    # Call Graph: getNavLockTxHeight | isHTLCTxnSpent -> _listBlsctUnspent
    def _listBlsctUnspent(self) -> list:
        return self.rpc_wallet("listblsctunspent", [0])

    # [_parseHtlcImportMsg]
    # Side: Both
    # Call Graph: importItxAndRescanChain | importPtxAndApplyToBid -> _parseHtlcImportMsg
    @staticmethod
    def _parseHtlcImportMsg(msg_bytes):
        offset = 0
        bid_id = msg_bytes[offset: offset + 28]
        offset += 28
        lock_value = int.from_bytes(msg_bytes[offset: offset + 4], "big")
        offset += 4
        addr_b_len = msg_bytes[offset]
        offset += 1
        nav_addr_refund = msg_bytes[offset: offset + addr_b_len].decode()
        offset += addr_b_len
        rescan_from = int.from_bytes(msg_bytes[offset: offset + 4], "big")
        offset += 4
        return bid_id, lock_value, nav_addr_refund, rescan_from

    # [MessageHandler: NAV_ITX_IMPORT]
    # Side: Bidder
    # Call Graph: update -> processMsg[NAV_ITX_IMPORT]
    def processNavItxImport(self, msg) -> None:
        msg_bytes = self._sc.getSmsgMsgBytes(msg)
        bid_id = msg_bytes[:28]

        # If bid_id is in swaps_in_progress, update the object there
        # and save to the db. Otherwise, modify the bid object in the db
        # so that later the bid in db will be added to swaps_in_progress
        if bid_id in self._sc.swaps_in_progress:
            bid = self._sc.swaps_in_progress[bid_id][0]
        else:
            bid = self._sc.getBid(bid_id)

        bid.nav_itx_import_info = msg_bytes
        # NAV_ITX_IMPORT may arrive after BID_ACCEPT; if initiate_tx already set, process immediately
        # rather than waiting for the next processBidAccept drain.
        if bid.initiate_tx is not None:
            self.importItxAndRescanChain(bid_id, bid)
        self._sc.saveBid(bid_id, bid)

    # [MessageHandler: NAV_PTX_IMPORT]
    # Side: Offerer
    # Call Graph: update -> processMsg[NAV_PTX_IMPORT]
    def processNavPtxImport(self, msg) -> None:
        msg_bytes = self._sc.getSmsgMsgBytes(msg)
        bid_id = msg_bytes[:28]
        # PTX import always arrives after the offerer accepted and the ITX confirmed,
        # so the bid is already in swaps_in_progress; mutate that live object so
        # checkBidState (which reads the in-memory bid) sees nav_ptx_import_info.
        bid = self._sc.swaps_in_progress[bid_id][0]
        bid.nav_ptx_import_info = msg_bytes
        self._sc.saveBid(bid_id, bid)

    # [MessageHandler: NAV_SECRET_REVEAL]
    # Side: Bidder
    # Call Graph: update -> processMsg[NAV_SECRET_REVEAL]
    def processNavSecretReveal(self, msg) -> None:
        msg_bytes = self._sc.getSmsgMsgBytes(msg)
        bid_id = msg_bytes[:28]
        secret = msg_bytes[28:60]

        self._sc.log.info(f"Received NAV secret reveal for bid {self._sc.log.id(bid_id)}")
        if bid_id not in self._sc.swaps_in_progress:
            self._sc.log.warning(f"processNavSecretReveal: bid {self._sc.log.id(bid_id)} not in progress")
            return

        bid = self._sc.swaps_in_progress[bid_id][0]
        if bid.was_received:
            self._sc.log.debug(f"processNavSecretReveal: offerer ignoring own reveal for bid {self._sc.log.id(bid_id)}")
            return

        bid.recovered_secret = secret
        # NAV PTx was spent by the offerer to reveal the secret — mark it redeemed
        if bid.participate_tx:
            bid.setPTxState(TxStates.TX_REDEEMED)
        delay = self._sc.get_short_delay_event_seconds()
        self._sc.log.info(f"Redeeming ITX for bid {self._sc.log.id(bid_id)} in {delay} seconds.")
        self._sc.createAction(delay, ActionTypes.REDEEM_ITX, bid_id)
        self._sc.saveBid(bid_id, bid)

    # [participateToBid]
    # Side: Bidder
    # Call Graph: update -> checkBidState[BID_ACCEPTED] -> initiateTxnConfirmed
    def publishPtxAndSendImportMsg(self, bid_id, bid, offer, txn, nav_ptx_import_payload) -> None:
        txid = self.publishTx(bytes.fromhex(txn))
        self._sc.log.debug(f"Submitted participate tx {self._sc.logIDT(txid)} to {self.coin_name()} chain for bid {self._sc.log.id(bid_id)}")
        self._sc.sendMessage(bid.bid_addr, offer.addr_from, nav_ptx_import_payload, self._sc.SMSG_SECONDS_IN_HOUR * 2, None)
        self._sc.log.info(f"Sent NAV_PTX_IMPORT to offer creator for bid {self._sc.log.id(bid_id)}")
        bid.setPTxState(TxStates.TX_SENT)
        self._sc.logEvent(Concepts.BID, bid.bid_id, EventLogTypes.PTX_PUBLISHED, "", None)

    # [publishTx]
    # Side: Both
    # Call Graph: acceptBid | publishPtxAndSendImportMsg -> publishTx
    def publishTx(self, tx: bytes):
        try:
            res = self.rpc("sendrawtransaction", [tx.hex()])
        except Exception as e:
            if self.isTxNonFinalError(str(e)):
                raise TemporaryError(str(e))
            raise
        return res

    # [participateTxnConfirmed]
    # Side: Offerer
    # Call Graph: update -> checkBidState[SWAP_INITIATED] -> participateTxnConfirmed
    def sendNavSecretReveal(self, bid_id, bid, offer) -> None:
        # NAV uses BLSCT (private txns) so bidder can't observe the secret from the chain directly.
        # Offerer explicitly sends the secret to bidder so bidder can redeem the ITX (non-NAV side).
        bid_date = dt.datetime.fromtimestamp(bid.created_at).date()
        secret = self._sc.getContractSecret(bid_date, bid.contract_count)
        payload_hex = str.format("{:02x}", MessageTypes.NAV_SECRET_REVEAL) + bid_id.hex() + secret.hex()
        self._sc.sendMessage(offer.addr_from, bid.bid_addr, payload_hex, self._sc.SMSG_SECONDS_IN_HOUR, None)

    # [signBlsct]
    # Side: Both
    # Call Graph: acceptBid | createParticipateTxn | createRedeemTxn -> signBlsct
    def signBlsct(self, txn):
        signed_txn = self.rpc("signblsctrawtransaction", [txn])
        return signed_txn

    # [checkBidState / SWAP_INITIATED]
    # Side: Offerer
    # Call Graph: update -> checkBidState[SWAP_INITIATED]
    def tryToGetNavPtxInfoFromChain(self, bid, participate_txid):
        # Search by secret hash via listblsctunspent; BLSCT outputs have no visible address
        if bid.participate_tx is None or bid.participate_tx.script is None:
            return None
        secret_hash = atomic_swap_1.extractScriptSecretHash(bid.participate_tx.script)
        lock_val = self.extractHTLCLockVal(bid.participate_tx.script, is_nav=False)
        return self.getNavLockTxHeight(
            participate_txid,
            secret_hash.hex(),
            bid.amount_to,
            bid.chain_b_height_start,
            lock_val=lock_val,
        )

    # [checkBidState / SWAP_INITIATED]
    # Side: Offerer
    # Call Graph: update -> checkBidState[SWAP_INITIATED]
    def updatePtxOutidAndState(self, bid, coin_to, found) -> bool:
        save_bid = False
        if bid.participate_tx.conf != found["depth"]:
            save_bid = True

        # NAV txid changes after aggregation — track by outid instead
        # Offerer: set txid from outid once known (bidder already has it from createParticipateTxn)
        if not bid.was_sent and bid.participate_tx.txid is None:
            outid = found.get("outid", None)
            if outid:
                bid.participate_tx.txid = bytes.fromhex(outid)
                save_bid = True

        if (
            bid.participate_tx.conf is None
            and bid.participate_tx.state != TxStates.TX_SENT
        ):
            bid.participate_tx.chain_height = self._sc.setLastHeightCheckedStart(coin_to, found["height"])
            if bid.participate_tx.state is None or bid.participate_tx.state < TxStates.TX_SENT:
                bid.setPTxState(TxStates.TX_SENT)
            save_bid = True
        return save_bid

    # [verifyProofOfFunds]
    # Side: Both
    # Call Graph: processBid -> verifyProofOfFunds
    def verifyProofOfFunds(self, address, signature, utxos, extra_commit_bytes):
        additional_commitment = extra_commit_bytes.hex()
        result = self.rpc(
            "verifyblsctbalanceproof", [signature, additional_commitment]
        )
        if not result.get("valid", False):
            raise ValueError("BLSCT balance proof invalid")
        min_amount_btc = result["min_amount"]
        return int(round(min_amount_btc * 100_000_000))

    # [verifyRawTransaction]
    # Side: Both
    # Call Graph: createRedeemTxn | createRefundTxn -> verifyRawTransaction
    def verifyRawTransaction(self, txn, prevouts):
        del prevouts
        res = self.rpc("testmempoolaccept", [[txn]])

        ro = {
            "inputs_valid": True,
            "validscripts": 1,
        }
        return ro
