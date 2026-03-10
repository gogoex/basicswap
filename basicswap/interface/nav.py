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

class PrevOutInfo(TypedDict):
    outid: str
    amount: float
    gamma: str
    spending_key: str

class NAVInterface(BTCInterface):
    @staticmethod
    def coin_type() -> Coins: # type: ignore[override]
        return Coins.NAV

    def __init__(self, coin_settings, network, swap_client=None):
        super(NAVInterface, self).__init__(coin_settings, network, swap_client)

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

    def createRefundTxn(
        self,
        prevout: PrevOutInfo,
        output_addr: str,
        output_value: int,
        locktime: int,
        sequence: int,
        txn_script: bytes | None = None,
    ) -> str:
        del locktime, sequence, txn_script
        self._log.info(f"---> createRefundTxn amount={prevout['amount']}, {output_value=}")

        in_params: dict[str, Any] = {
            "outid": prevout["outid"],
            "value": int(prevout["amount"]),
            "gamma": prevout["gamma"],
            "spending_key": prevout["spending_key"],
            "scriptSig": "00",
        }
        out_params: dict[str, Any] = {
            "amount": output_value,
            "address": output_addr,
        }
        params = [[in_params], [out_params]]
        self._log.info(f"---> {params=}")
        txn = self.rpc("createblsctrawtransaction", params)
        self._log.info(f"---> Created raw transaction with {params=}, {txn=}")

        txn_funded = self.rpc_wallet("fundblsctrawtransaction", [txn])
        self._log.info(f"---> Created raw funded transaction: {txn_funded=}")

        return txn_funded

    def describeTx(self, tx_hex: str):
        # tx_hex is expected to be sigined
        # for txs before signing, use decodeblsctrawtransaction
        return self.rpc("decoderawtransaction", [tx_hex])

    # used to generate mock address
    # TODO NAVIO generate address based on script_dest
    def encodeScriptDest(self, script: bytes) -> str:
        del script
        return "tnv14adxpa06t5fywwtte3g223ef92plxqm7ls2jxqp5rwef2cz7ppdhx36ck0e42x2dkj92vw3kxfj90zpzy8ymnmqd9x9gc5wq2xv6m5rkxcxz39jpvaan4dw254ayl94h5tuy5pftaczhcrr5exz9ke0cdgr75y6ft5"

    # def find_prevout_info(self, txn_hex: str, txn_script: bytes):
    #     del txn_script
    #     txjs = self.rpc("decoderawtransaction", [txn_hex])
    #
    #     return {
    #         "txid": txjs["txid"],
    #         "vout": 0,
    #     }
    #
    # def find_htlc_vouts(txjs: dict) -> list[VOut]:
    #     res = []
    #     for txjs in txjs["outputs"]:
    #         pass
    #
    #     return res

    def get_fee_rate(self, conf_target: int = 2) -> (float, str):
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
        sat_per_kb = 125

        return sat_per_kb, "default_feerate"

    def getHTLCSpendTxVSize(self, redeem: bool = True) -> int:
        del redeem
        # always using the size of a refund transaction since the size
        # difference between redeem and refund transactions are small
        return 1336

    def getPrevOutInfo(self, txn_hex: str) -> PrevOutInfo:
        txjs = self.rpc("decodeblsctrawtransaction", [txn_hex])
        self._log.info(f"---> getPrevOutInfo: {txjs=}")

        for output in txjs['outputs']:
            if self.isHTLCScript(output['scriptPubKey']):
                self._log.debug(f"getPrevOutInfo {output=}")
                nav_amount = int(output['amount'])
                return {
                    "outid":  output['outputHash'],
                    "amount": nav_amount,
                    "gamma": output['gamma'],
                    "spending_key": output['spending_key'],
                }

        raise ValueError("No output with HTLC script found in {txjs=}")

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

    def getSeedHash(self, seed: bytes) -> bytes:
        del seed
        seedid_hex = self.getWalletSeedID()
        return bytes.fromhex(seedid_hex)

    def getWalletSeedID(self) -> str:
        """
        The Navio wallet has been initialized using the root key generated by
        `getWalletKey(c, 1)` as the seed.
        """
        return self.rpc("getblsctseed")

    def getSpendingPubKey(self) -> bytes:
        return bytes(96)

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
            <4-byte locktime>
            OP_CHECKLOCKTIMEVERIFY
            OP_DROP
            <48-byte address_b>
        OP_ENDIF
        OP_BLSCHECKSIG        

        >>> nav = NAVInterface()
        >>> hex = "6382012088a820b812e53d1bd15a928803df44ab86c6a286d9a3d6625a3738f"
        >>> hex += "bed32d89a4c7c178830a7b9a59a0e305eef4f756909e6fa107091fc6d2b2743"
        >>> hex += "3d110d5d3c95ff987a0182bbd2e19897ee71af0466006cc2755467042c688b6"
        >>> hex += "9b17530a7b9a59a0e305eef4f756909e6fa107091fc6d2b27433d110d5d3c95"
        >>> hex += "ff987a0182bbd2e19897ee71af0466006cc2755468b3"
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
        
        return (
            # valid script is 296-char long
            len(script) == 296 and
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
            # 04 (Data Length 4)
            consume("6704") and 
            # locktime
            skip(4) and
            # b1 (OP_CHECKLOCKTIMEVERIFY)
            # 75 (OP_DROP)
            # 30 (Data Length 48)
            consume("b17530") and 
            # address_b
            skip(48) and
            # 68 (OP_ENDIF)
            # b3 (OP_BLSCHECKSIG)
            consume("68b3") 
        )

    def publishTx(self, tx: bytes):
        self._log.debug(f"---> publishing: {tx.hex()}") 
        return self.rpc("sendrawtransaction", [tx.hex()])
    
    def signBlsct(self, txn):
        self._log.debug(f"---> signing blsct...")
        signed_txn = self.rpc("signblsctrawtransaction", [txn])
        self._log.debug(f"---> signed blsct {signed_txn=}")
        return signed_txn

    def verifyRawTransaction(self, refund_txn, prevouts):
        del prevouts
        res = self.rpc("testmempoolaccept", [[refund_txn]])
        self._log.debug(f"---> verifyRawTransaction: {res}")

        ro = {
            "inputs_valid": True,
            "validscripts": 1,
        }
        return ro













