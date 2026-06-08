# -*- coding: utf-8 -*-

# Copyright (c) 2025 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import basicswap.protocols.atomic_swap_1 as atomic_swap_1
from basicswap.basicswap_util import EventLogTypes, TxStates
from basicswap.chainparams import Coins
from basicswap.db import Concepts
from basicswap.util import ensure


# [processBidAccept / processNavItxImport]
# Side: Bidder
# Call Graph: processMsg[BID_ACCEPT] -> processBidAccept
#             processMsg[NAV_ITX_IMPORT] -> processNavItxImport
def import_nav_itx_and_rescan_nav_chain(sc, bid_id, bid) -> None:
    if bid.nav_itx_import_info is None:
        return
    ci_nav = sc.ci(Coins.NAV)
    _, blinding_key, lock_value, nav_addr_redeem, nav_addr_refund, rescan_from, tx_data_funded_bytes = ci_nav._parseHtlcImportMsg(bid.nav_itx_import_info)
    secret_hash = atomic_swap_1.extractScriptSecretHash(bid.initiate_tx.script)
    params = ci_nav._buildImportBlsctScriptParams(
        nav_addr_redeem, nav_addr_refund, secret_hash, lock_value, blinding_key,
    )
    ci_nav.importBlsctScript(params, rescan_from)
    sc.log.info(f"Imported NAV ITX HTLC script for bid {sc.log.id(bid_id)}")
    # Update initiate_tx.script to fake BLSCT format (with absolute locktime) so
    # isHTLCTxnSpent can match the on-chain UTxO locktime correctly.
    bid.initiate_tx.script = ci_nav.createFakeNonNavHTLCScript(secret_hash, lock_value)
    # ITx is already on-chain when bidder imports; rescanblockchain finds the existing UTXO
    if rescan_from is not None:
        try:
            chain_height = ci_nav.rpc("getblockchaininfo")["blocks"]
            rescan_from = min(rescan_from, chain_height)
        except Exception as e:
            sc.log.warning(f"import_nav_itx_and_rescan_nav_chain: could not clamp rescan_from: {e}")
        sc.log.info(f"Rescanning from height {rescan_from} to find ITX UTXO")
        ci_nav.rpc_wallet("rescanblockchain", [rescan_from])
        sc.log.info(f"Rescan complete")
    ensure(tx_data_funded_bytes is not None, "NAV_ITX_IMPORT missing tx_data_funded")
    ensure(bid.initiate_tx.tx_data_funded is None, "NAV ITX tx_data_funded already set")
    bid.initiate_tx.tx_data_funded = tx_data_funded_bytes
    bid.nav_itx_import_info = None

# [checkBidState / SWAP_INITIATED]
# Side: Offerer
# Call Graph: update -> checkBidState[SWAP_INITIATED]
def import_nav_ptx_and_apply_to_bid(sc, bid_id, bid) -> bool:
    if bid.nav_ptx_import_info is None:
        return False
    ci_nav = sc.ci(Coins.NAV)
    _, blinding_key, lock_value, nav_addr_redeem, nav_addr_refund, rescan_from, tx_data_funded_bytes = ci_nav._parseHtlcImportMsg(bid.nav_ptx_import_info)
    secret_hash = atomic_swap_1.extractScriptSecretHash(bid.initiate_tx.script)
    params = ci_nav._buildImportBlsctScriptParams(
        nav_addr_redeem, nav_addr_refund, secret_hash, lock_value, blinding_key,
    )
    ci_nav.importBlsctScript(params, rescan_from)
    sc.log.info(f"Imported NAV PTX HTLC script for bid {sc.log.id(bid_id)}")
    ensure(tx_data_funded_bytes is not None, "NAV_PTX_IMPORT missing tx_data_funded")
    fake_script = ci_nav.createFakeNonNavHTLCScript(secret_hash, lock_value)
    bid.participate_tx.script = fake_script
    bid.participate_tx.tx_data_funded = tx_data_funded_bytes
    bid.nav_ptx_import_info = None
    return True

# [participateToBid]
# Side: Bidder
# Call Graph: update -> checkBidState[BID_ACCEPTED] -> initiateTxnConfirmed
def publish_nav_ptx_and_send_ptx_import_msg(sc, bid_id, bid, offer, ci_to, txn, nav_ptx_import_payload) -> None:
    txid = ci_to.publishTx(bytes.fromhex(txn))
    sc.log.debug(f"Submitted participate tx {sc.logIDT(txid)} to {ci_to.coin_name()} chain for bid {sc.log.id(bid_id)}")
    sc.sendMessage(bid.bid_addr, offer.addr_from, nav_ptx_import_payload, sc.SMSG_SECONDS_IN_HOUR * 2, None)
    sc.log.info(f"Sent NAV_PTX_IMPORT to offer creator for bid {sc.log.id(bid_id)}")
    bid.setPTxState(TxStates.TX_SENT)
    sc.logEvent(Concepts.BID, bid.bid_id, EventLogTypes.PTX_PUBLISHED, "", None)

