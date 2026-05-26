# -*- coding: utf-8 -*-

# Copyright (c) 2023 tecnovert
# Copyright (c) 2024-2025 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from basicswap.interface.btc import (
    BTCInterface,
)
from basicswap.chainparams import Coins
from typing import Optional, Any, TypedDict
from basicswap.basicswap_util import TxLockTypes
from basicswap.util import SerialiseNum, TemporaryError
from basicswap.util.crypto import sha256
from coincurve.keys import PrivateKey
import basicswap.protocols.atomic_swap_1 as atomic_swap_1

class PrevOutInfo(TypedDict):
    outid: str
    amount: float  # NAV coins from decodeblsctrawtransaction
    gamma: str

class PrevOutInfoWithSpendingKey(PrevOutInfo):
    spending_key: str

class PtxInfoOfferer(TypedDict):
    script: bytearray
    tx_data_funded: bytes

class NAVInterface(BTCInterface):
    @staticmethod
    def coin_type() -> Coins: # type: ignore[override]
        return Coins.NAV

    def __init__(self, coin_settings, network, swap_client=None):
        super(NAVInterface, self).__init__(coin_settings, network, swap_client)
        self._ptx_info_offerer: dict = {}

    def checkExpectedSeed(self, expect_seedid: str) -> bool:
        RPC_WALLET_BLANK = -37
        try:
            actual_seedid = self.getWalletSeedID()
        except Exception as e:
            if str(RPC_WALLET_BLANK) in str(e):
                return False
            raise
        return expect_seedid == actual_seedid

    def clearPtxData(self, bid_id: bytes) -> None:
        self._ptx_info_offerer.pop(bid_id, None)

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

    def createInitiateTxn(
        self,
        address_a: str,
        address_b: str,
        hash: bytes,
        locktime: int,
        blinding_key: int,
        amount: int,
        timelock_opcode: str,
    ) -> tuple[str, int]:
        param: dict[str, Any] = {
            "amount": amount,
            "address_a": address_a,
            "address_b": address_b,
            "blinding_key": f"{blinding_key:064x}",
            "hash": hash.hex(),
            "locktime": locktime,
            "timelock_opcode": timelock_opcode,
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

    def createRawSignedTransaction(self, addr_to, amount) -> str:
        txn_funded = self._createRawFundedTransaction(addr_to, amount)
        return self.rpc_wallet("signblsctrawtransaction", [txn_funded])

    def createRedeemTxn(
        self,
        prevout: PrevOutInfoWithSpendingKey, # amount is in NAV
        output_addr: str,
        output_value: int, # in Navoshis
        txn_script: bytes | None = None,
    ) -> str:
        in_params: dict[str, Any] = {
            "outid": prevout["outid"],
            "value": self.make_int(prevout["amount"]),  # NAV to Navoshis
            "gamma": prevout["gamma"],
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

    def deriveBlindingKey(self, privkey: bytes, pubkey: bytes) -> int:
        """Derive a blinding key via ECDH: SHA256(ECDH(privkey, pubkey))."""

        ecdh_secret = PrivateKey(privkey).ecdh(pubkey)
        blinding_key_bytes = sha256(ecdh_secret)
        return int.from_bytes(blinding_key_bytes, "big")

    def deriveSpendingKey(self, blinding_key_hex: str, address: str) -> str:
        """Derive the private spending key for a BLSCT HTLC output.
        Uses rpc_wallet because the address must be owned by this wallet."""
        return self.rpc_wallet("deriveblsctspendingkey", [blinding_key_hex, address])

    def describeTx(self, tx_hex: str):
        # tx_hex is expected to be sigined
        # for txs before signing, use decodeblsctrawtransaction
        return self.rpc("decoderawtransaction", [tx_hex])


    def extractHTLCLockVal(self, script: bytes, is_nav: bool) -> int:
        if is_nav:
            push_size = script[90]
            locktime_bytes = script[91:91 + push_size]
        else:
            push_size = script[64]
            locktime_bytes = script[65:65 + push_size]
        return int.from_bytes(locktime_bytes, byteorder='little')

    # Workaround: naviod crashes with getblock verbosity=2 (MoneyRange assertion). Remove once naviod fixes.
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

    def getHTLCSpendTxVSize(self, redeem: bool = True) -> int:
        del redeem
        # always using the size of a refund transaction since the size
        # difference between redeem and refund transactions are small
        return 1336

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
                    }
                    self._log.info(f"getNavLockTxHeight found HTLC via listblsctunspent: {rv}")
                    return rv
        except Exception as e:
            self._log.error(f"getNavLockTxHeight listblsctunspent search failed: {e}")

        return None

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

    def getProofOfFunds(self, amount_for, extra_commit_bytes):
        amount_btc = amount_for / 100_000_000
        additional_commitment = extra_commit_bytes.hex()
        result = self.rpc_wallet(
            "createblsctbalanceproof", [amount_btc, additional_commitment]
        )
        proof_hex = result["proof"]
        return ("blsct_balance_proof", proof_hex, [])

    def getPtxInfoOfferer(self, bid_id: bytes) -> PtxInfoOfferer | None:
        return self._ptx_info_offerer.get(bid_id, None)

    def getSeedHash(self, seed: bytes) -> bytes:
        return seed

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

    def getWalletSeedID(self) -> str:
        """
        The Navio wallet has been initialized using the root key generated by
        `getWalletKey(c, 1)` as the seed.
        """
        return self.rpc("getblsctseed")

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

    # TODO NAV write test
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

    def isTxNonFinalError(self, err_str: str) -> bool:
        # non-final-input: refund submitted before CLTV locktime expires
        # bad-inputs-unknown: refund input not in UTXO set; PTX still in mempool (BLSCT outputs unspendable until confirmed)
        return "non-final-input" in err_str or "bad-input-unknown" in err_str or "bad-inputs-unknown" in err_str or "'code': 25" in err_str

    def _listBlsctUnspent(self) -> list:
        return self.rpc_wallet("listblsctunspent", [0])

    def publishTx(self, tx: bytes):
        try:
            res = self.rpc("sendrawtransaction", [tx.hex()])
        except Exception as e:
            if self.isTxNonFinalError(str(e)):
                raise TemporaryError(str(e))
            raise
        return res

    def signBlsct(self, txn):
        signed_txn = self.rpc("signblsctrawtransaction", [txn])
        return signed_txn

    def stashPtxOfferer(self, bid_id: bytes, script: bytearray, tx_data_funded: bytes) -> None:
        self._ptx_info_offerer[bid_id] = PtxInfoOfferer(script=script, tx_data_funded=tx_data_funded)

    def verifyProofOfFunds(self, address, signature, utxos, extra_commit_bytes):
        additional_commitment = extra_commit_bytes.hex()
        result = self.rpc(
            "verifyblsctbalanceproof", [signature, additional_commitment]
        )
        if not result.get("valid", False):
            raise ValueError("BLSCT balance proof invalid")
        min_amount_btc = result["min_amount"]
        return int(round(min_amount_btc * 100_000_000))

    def verifyRawTransaction(self, txn, prevouts):
        del prevouts
        res = self.rpc("testmempoolaccept", [[txn]])

        ro = {
            "inputs_valid": True,
            "validscripts": 1,
        }
        return ro
