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
from basicswap.util import SerialiseNum
from basicswap.util.crypto import sha256
from coincurve.keys import PrivateKey
import basicswap.protocols.atomic_swap_1 as atomic_swap_1

class PrevOutInfo(TypedDict):
    outid: str
    amount: int
    gamma: str
    spending_key: str

class NAVInterface(BTCInterface):
    @staticmethod
    def coin_type() -> Coins: # type: ignore[override]
        return Coins.NAV

    def __init__(self, coin_settings, network, swap_client=None):
        super(NAVInterface, self).__init__(coin_settings, network, swap_client)
        self._ptx_data_funded: dict = {}

    def stashPtxDataFunded(self, bid_id: bytes, tx_data_funded: bytes) -> None:
        self._ptx_data_funded[bid_id] = tx_data_funded

    def popPtxDataFunded(self, bid_id: bytes) -> bytes | None:
        return self._ptx_data_funded.pop(bid_id, None)

    def checkExpectedSeed(self, expect_seedid: str) -> bool:
        actual_seedid = self.getWalletSeedID()
        return expect_seedid == actual_seedid

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
        self._log.info(f"---> in _createRawFundedTransaciton: {addr_to=}, {amount=}")

        param: dict[str, Any] = {
            "address": addr_to,
            "amount": amount,
        }
        if script is not None:
            param["script"] = bytes(script).hex()
            self._log.info(f"---> Added script")
        self._log.info(f"---> {param=}")
        params = [param]

        txn = self.rpc("createblsctrawtransaction", [[], params])
        self._log.info(f"---> Created raw transaction with {params=}, {txn}")

        txn_funded = self.rpc_wallet("fundblsctrawtransaction", [txn])
        self._log.info(f"---> Created raw funded transaction")
        return txn_funded

    def createFakeNonNavHTLCScript(self, secret_hash: bytearray, locktime: int) -> bytearray:
        """
        Create a non-NAV HTLC script with zeroed-out fields,
        excluding the secret hash and locktime.
        """
        padded_secret_hash = secret_hash.rjust(32, b'\x00')
        locktime_bytes = locktime.to_bytes(max(1, (locktime.bit_length() + 7) // 8), byteorder='little')
        fake_script = (
            b'\x00' * 7 +
            padded_secret_hash +
            b'\x00' * 25 +
            bytes([len(locktime_bytes)]) +
            locktime_bytes
        )
        return bytearray(fake_script)

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

    def createInitiateTxn(
        self,
        address_a: str,
        address_b: str,
        hash: bytes,
        locktime: int,
        blinding_key: int,
        amount: int,
    ) -> tuple[str, int]:
        self._log.info(f"---> createInitiateTxn")
        param: dict[str, Any] = {
            "amount": amount,
            "address_a": address_a,
            "address_b": address_b,
            "blinding_key": f"{blinding_key:064x}",
            "hash": hash.hex(),
            "locktime": locktime,
            "type": "atomic_swap",
        }
        self._log.info(f"---> {param=}")
        params = [param]
        txn = self.rpc("createblsctrawtransaction", [[], params])
        self._log.info(f"---> createInitiateTxn: created raw non-funded tx: {txn=}")

        txn_funded = self.rpc_wallet("fundblsctrawtransaction", [txn])
        txjs = self.rpc_wallet("decodeblsctrawtransaction", [txn_funded])
        self._log.info(f"---> createInitiateTxn: created raw funded tx: {txn_funded=}")

        vout_index = None
        for index, output in enumerate(txjs["outputs"]):
            if self.isHTLCScript(output["scriptPubKey"]):
                vout_index = index
                break
        if vout_index is None:
            raise ValueError(f"Failed to find vout with HTLC script")
        self._log.info(f"vout index is {vout_index}") 

        return txn_funded, vout_index

    def createRedeemTxn(
        self,
        prevout: PrevOutInfo, # amount is in Navoshis
        output_addr: str,
        output_value: int, # in Navoshis
        txn_script: bytes | None = None,
    ) -> str:
        self._log.info(f"---> createReedemTxn amount={prevout['amount']}, {output_value=}, {prevout=}")
        in_params: dict[str, Any] = {
            "outid": prevout["outid"],
            "value": int(prevout["amount"]),
            "gamma": prevout["gamma"],
            "spending_key": prevout["spending_key"],
            "scriptSig": txn_script.hex(),
        }
        out_params: dict[str, Any] = {
            "amount": int(output_value),
            "address": output_addr,
        }
        params = [[in_params], [out_params]]
        self._log.info(f"---> {params=}")
        txn = self.rpc("createblsctrawtransaction", params)
        self._log.info(f"---> Created raw transaction with {txn=}")

        fee = int(prevout["amount"]) - output_value
        txn_funded = self.rpc_wallet("fundblsctrawtransaction", [txn, None, False, fee])
        self._log.info(f"---> Created raw funded transaction: {txn_funded=}")

        return txn_funded

    def createRefundTxn(
        self,
        prevout: PrevOutInfo, # amount is in Navoshis
        output_addr: str,
        output_value: int, # in NAV
        locktime: int,
        sequence: int,
        txn_script: bytes | None = None,
    ) -> str:
        del sequence, txn_script 
        navoshi_output_value = self.make_int(output_value, r=1)
        del output_value
        self._log.info(f"---> createRefundTxn amount={prevout['amount']}, {navoshi_output_value=}")

        in_params: dict[str, Any] = {
            "outid": prevout["outid"],
            "value": int(prevout["amount"]),
            "gamma": prevout["gamma"],
            "spending_key": prevout["spending_key"],
            "scriptSig": "00", # select else path
        }
        out_params: dict[str, Any] = {
            "amount": navoshi_output_value,
            "address": output_addr,
            "locktime": locktime,
        }
        params = [[in_params], [out_params]]
        txn = self.rpc("createblsctrawtransaction", params)
        self._log.info(f"---> Creating refund txn w/ {params=}")

        fee = prevout["amount"] - navoshi_output_value
        txn_funded = self.rpc_wallet("fundblsctrawtransaction", [txn, None, False, fee])
        self._log.info(f"---> Created funded refund transaction")

        return txn_funded

    def deriveBlindingKey(self, privkey: bytes, pubkey: bytes) -> int:
        """Derive a blinding key via ECDH: SHA256(ECDH(privkey, pubkey))."""
        self._log.info(f"---> deriveBlindingKey priv={privkey.hex()}")
        self._log.info(f"---> deriveBlindingKey pub={pubkey.hex()}")

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

    # # used to generate mock address
    # # TODO NAVIO generate address based on script_dest
    # def encodeScriptDest(self, script: bytes) -> str:
    #     del script
    #     return "tnv14adxpa06t5fywwtte3g223ef92plxqm7ls2jxqp5rwef2cz7ppdhx36ck0e42x2dkj92vw3kxfj90zpzy8ymnmqd9x9gc5wq2xv6m5rkxcxz39jpvaan4dw254ayl94h5tuy5pftaczhcrr5exz9ke0cdgr75y6ft5"

    def extractHTLCLocktime(self, script: bytes, is_nav: bool) -> int:
        """
        >>> hex = "6382012088a820b812e53d1bd15a928803df44ab86c6a286d9a3d6625a3738f"
        >>> hex += "bed32d89a4c7c178830a7b9a59a0e305eef4f756909e6fa107091fc6d2b2743"
        >>> hex += "3d110d5d3c95ff987a0182bbd2e19897ee71af0466006cc2755467042c688b6"
        >>> hex += "9b17530a7b9a59a0e305eef4f756909e6fa107091fc6d2b27433d110d5d3c95"
        >>> hex += "ff987a0182bbd2e19897ee71af0466006cc2755468b3"
        >>> b = bytes.fromhex(hex)
        >>> nav = NAVInterface()
        >>> nav.extractHTLCLocktime(b, is_nav=True)
        1770743852
        """
        if is_nav:
            locktime_bytes = script[91:95]
        else:
            push_size = script[64]
            locktime_bytes = script[65:65 + push_size]
        return int.from_bytes(locktime_bytes, byteorder='little')

    # TODO NAV remove this after getblock 2 issue is fixed
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

        # fixed fee in sat/kb
        navoshi_per_kb = 125
        fee_nav = navoshi_per_kb * 1e-8

        return fee_nav, "default_feerate" 

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
        find_index: bool = False,
        vout: int = -1,
        *,
        locktime: int,
    ):
        """BLSCT outputs don't have standard addresses, and tx hashes change
        after block aggregation.  Search listblsctunspent for the HTLC output
        matching dest_address (which contains the secret_hash for NAV). """
        del bid_amount, rescan_from, txid, find_index, vout
        self._log.info(f"---> getLockTxHeight: {dest_address=}")
        if not dest_address:
            return None

        secret_hash = dest_address.lower()
        try:
            utxos = self.listBlsctUnspent(min_conf=0)
            for utxo in utxos:
                utxo_spk = utxo.get("scriptPubKey", "").lower()
                if not self.isHTLCScript(utxo_spk):
                    continue
                spk_secret_hash = atomic_swap_1.extractScriptSecretHash(bytes.fromhex(utxo_spk)).hex()
                spk_locktime = self.extractHTLCLocktime(bytes.fromhex(utxo_spk), is_nav=True)

                if spk_secret_hash == secret_hash and spk_locktime == locktime:
                    confirmations = utxo.get("confirmations", 0)
                    chain_info = self.rpc("getblockchaininfo")
                    chain_height = chain_info["blocks"]
                    block_height = max(0, chain_height - confirmations + 1) if confirmations > 0 else 0
                    rv = {
                        "depth": confirmations,
                        "height": block_height,
                        # Try "outid" first (rc18+), fall back to "outputHash" (rc15)
                        "outid": utxo.get("outid", None) or utxo.get("outputHash", ""),
                    }
                    self._log.info(f"getLockTxHeight found HTLC via listblsctunspent: {rv}")
                    return rv
        except Exception as e:
            self._log.error(f"getLockTxHeight listblsctunspent search failed: {e}")

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

    def getParticipateLockValue(self, bid, offer, bid_id, ci_from) -> int:
        """Calculate the locktime/sequence for the NAV participate tx.
        The participate tx is locked for half the time of the initiate tx.
        Returns an absolute block height or timestamp for use as CLTV locktime in createInitiateTxn.
        NAV HTLC always uses CLTV, so CSV sequence values must be converted to absolute values.
        """
        lock_value = offer.lock_value // 2
        block_header = ci_from.getBlockHeaderFromHeight(bid.initiate_tx.chain_height)
        initiate_tx_block_time = block_header["time"]

        if offer.lock_type in (TxLockTypes.SEQUENCE_LOCK_BLOCKS, TxLockTypes.ABS_LOCK_BLOCKS):
            block_header_at = self.getBlockHeaderAt(initiate_tx_block_time, block_after=True)
            return block_header_at["height"] + lock_value
        else:
            # SEQUENCE_LOCK_TIME and ABS_LOCK_TIME: return absolute timestamp
            return initiate_tx_block_time + lock_value

    def getPrevOutInfoFromOffChainTxn(self, txn_hex: str, secret_hash: bytes) -> PrevOutInfo:
        txjs = self.rpc_wallet("decodeblsctrawtransaction", [txn_hex])
        self._log.debug(f"getPrevOutInfoFromOffChainTxn: secret_hash={secret_hash.hex()}")
        for output in txjs.get("outputs", []):
            spk = output.get("scriptPubKey", "")
            if not self.isHTLCScript(spk):
                continue
            spk_secret_hash = atomic_swap_1.extractScriptSecretHash(bytes.fromhex(spk))
            self._log.debug(f"found HTLC script: spk_secret_hash={spk_secret_hash.hex()}")
            if secret_hash == spk_secret_hash:
                self._log.info(f"---> got NAV prevout (off-chain)={output}")
                return {
                    "outid": output["outputHash"],
                    "amount": output["amount"],
                    "gamma": output["gamma"],
                    "spending_key": output["spending_key"],
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

    def getSeedHash(self, seed: bytes) -> bytes:
        del seed
        seedid_hex = self.getWalletSeedID()
        return bytes.fromhex(seedid_hex)

    def getSpendingPubKey(self) -> bytes:
        return bytes(96)

    def getWalletSeedID(self) -> str:
        """
        The Navio wallet has been initialized using the root key generated by
        `getWalletKey(c, 1)` as the seed.
        """
        return self.rpc("getblsctseed")

    def importBlsctScript(self, params: dict, rescan: bool = False) -> dict:
        return self.rpc_wallet("importblsctscript", [params, rescan])

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

    def isHTLCScript(self, script: str) -> bool:
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
        >>> nav.isHTLCScript(hex)
        True
        >>> hex = "6382012088a8206756e66c48945a6851790e94fed56b86ec9d1e05116d4d289bf"
        >>> hex += "62f858389c3998830a6c43cded614e403d715cd7f28a57736214937dd811bd7e2927eed4cd"
        >>> hex += "904ee8df0066923c7dc021a36e94fa6f8fa21e36703710040b17530a769dfbee940c4f72c1"
        >>> hex += "29b5a315822dabda7932f5f12b8d1c56d2335544995504af3e11446a3b544cb6ec51403377"
        >>> hex += "33468b3"
        >>> nav.isHTLCScript(hex)
        True
        >>> nav.isHTLCScript("76a91488ac")
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
            # b1 (OP_CHECKLOCKTIMEVERIFY)
            # 75 (OP_DROP
            # 30 (Data Length 48)
            consume("b17530") and 
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
        locktime = self.extractHTLCLocktime(script, is_nav=False)
        self._log.debug(f"isHTLCTxnSpent: secret_hash={secret_hash.hex()} {locktime=} script={script.hex()}")
        try:
            utxos = self.listBlsctUnspent(min_conf=0)
            for utxo in utxos:
                spk = utxo.get("scriptPubKey", "")
                if not self.isHTLCScript(spk):
                    continue
                spk_bytes = bytes.fromhex(spk)
                spk_secret_hash = atomic_swap_1.extractScriptSecretHash(spk_bytes)
                spk_locktime = self.extractHTLCLocktime(spk_bytes, is_nav=True)
                if secret_hash == spk_secret_hash and locktime == spk_locktime:
                    self._log.debug(f"isHTLCTxnSpent: fonund matching utxo. not spent yet: {utxo=}")
                    return False
            self._log.debug(f"isHTLCTxnSpent: {secret_hash.hex()} is spent")
            return True

        except Exception as e:
            self._log.error(f"Failed to check if HTLC txn is spent: {e}")
        return False

    def isTxNonFinalError(self, err_str: str) -> bool:
        return "bad-inputs-unknown" in err_str or "'code': 25" in err_str
    
    def listBlsctUnspent(self, min_conf: int = 1) -> list:
        return self.rpc_wallet("listblsctunspent", [min_conf])

    def publishTx(self, tx: bytes):
        self._log.debug(f"---> publishing tx tx={tx.hex()}")
        res = self.rpc("sendrawtransaction", [tx.hex()])
        self._log.debug(f"---> result = {res=}")
        return res
    
    def signBlsct(self, txn):
        self._log.debug(f"---> signing blsct...")
        signed_txn = self.rpc("signblsctrawtransaction", [txn])
        self._log.debug(f"---> signed blsct {signed_txn=}")
        return signed_txn

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
        self._log.debug(f"---> verifyRawTransaction: {res}")

        ro = {
            "inputs_valid": True,
            "validscripts": 1,
        }
        return ro













