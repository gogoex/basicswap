# -*- coding: utf-8 -*-

# Copyright (c) 2025 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import datetime as dt

import basicswap.protocols.atomic_swap_1 as atomic_swap_1
from basicswap.basicswap_util import BidStates, EventLogTypes, MessageTypes, TxLockTypes, TxStates, TxTypes
from basicswap.chainparams import Coins
from basicswap.db import Concepts
from basicswap.util import ensure


def _build_import_blsct_script_params(nav_addr_redeem, nav_addr_refund, secret_hash, lock_value, blinding_key):
    return {
        "type": "atomic_swap",
        "address_a": nav_addr_redeem,
        "address_b": nav_addr_refund,
        "hash": secret_hash.hex(),
        "locktime": lock_value,
        "timelock_opcode": "cltv",
        "blinding_key": f"{blinding_key:064x}",
    }

def _build_nav_htlc_import_payload(msg_type, bid_id, blinding_key, lock_value, nav_addr_redeem, nav_addr_refund, chain_height, txn_funded):
    addr_a_bytes = nav_addr_redeem.encode()
    addr_b_bytes = nav_addr_refund.encode()
    tx_data_bytes = bytes.fromhex(txn_funded)
    return (
        format(int(msg_type), "02x")
        + bid_id.hex()
        + blinding_key.to_bytes(32, "big").hex()
        + lock_value.to_bytes(4, "big").hex()
        + format(len(addr_a_bytes), "02x")
        + addr_a_bytes.hex()
        + format(len(addr_b_bytes), "02x")
        + addr_b_bytes.hex()
        + chain_height.to_bytes(4, "big").hex()
        + len(tx_data_bytes).to_bytes(4, "big").hex()
        + tx_data_bytes.hex()
    )

def _parse_nav_htlc_import_msg(msg_bytes):
    offset = 0
    bid_id = msg_bytes[offset: offset + 28]
    offset += 28
    blinding_key = int.from_bytes(msg_bytes[offset: offset + 32], "big")
    offset += 32
    lock_value = int.from_bytes(msg_bytes[offset: offset + 4], "big")
    offset += 4
    addr_a_len = msg_bytes[offset]
    offset += 1
    nav_addr_redeem = msg_bytes[offset: offset + addr_a_len].decode()
    offset += addr_a_len
    addr_b_len = msg_bytes[offset]
    offset += 1
    nav_addr_refund = msg_bytes[offset: offset + addr_b_len].decode()
    offset += addr_b_len
    rescan_from = int.from_bytes(msg_bytes[offset: offset + 4], "big")
    offset += 4
    tx_data_funded_bytes = None
    if offset < len(msg_bytes):
        tx_data_len = int.from_bytes(msg_bytes[offset: offset + 4], "big")
        offset += 4
        tx_data_funded_bytes = msg_bytes[offset: offset + tx_data_len]
    return bid_id, blinding_key, lock_value, nav_addr_redeem, nav_addr_refund, rescan_from, tx_data_funded_bytes

# [checkBidState / SWAP_PARTICIPATING]
# Side: Bidder
# Call Graph: update -> checkBidState[SWAP_PARTICIPATING]
def handle_swap_participating(sc, bid_id, bid, coin_from, coin_to) -> bool:
    # NAV HTLC outputs have no visible address; isHTLCTxnSpent polls via listblsctunspent.
    # coin_from == NAV: ITX is NAV — check if ITX is spent to mark it TX_REDEEMED.
    # coin_to == NAV: PTX is NAV — check if PTX is spent; distinguish refund vs redeem via PTX_REFUND_PUBLISHED event.
    save_bid = False
    if coin_from == Coins.NAV and bid.initiate_tx is not None:
        if sc.ci(coin_from).isHTLCTxnSpent(bid.initiate_tx.script):
            bid.setITxState(TxStates.TX_REDEEMED)
            save_bid = True
    elif coin_to == Coins.NAV and bid.getPTxState() != TxStates.TX_REDEEMED:
        if sc.ci(coin_to).isHTLCTxnSpent(bid.participate_tx.script):
            events = sc.getEvents(int(Concepts.BID), bid_id)
            ptx_refund_published = any(e.event_type == int(EventLogTypes.PTX_REFUND_PUBLISHED) for e in events)
            bid.setPTxState(TxStates.TX_REFUNDED if ptx_refund_published else TxStates.TX_REDEEMED)
            save_bid = True
    return save_bid

# [acceptBid]
# Side: Offerer
# Call Graph: checkQueuedActions[ACCEPT_BID] -> acceptBid
def import_itx_and_send_payload_msg_to_bidder(sc, bid_id, bid, offer, ci_from, nav_addr_redeem, nav_addr_refund, secret_hash, lock_value, blinding_key, txn_funded, chain_height_before_submit, use_cursor):
    # Import HTLC script so wallet tracks the output after tx aggregation (txid changes when mined).
    params = _build_import_blsct_script_params(
        nav_addr_redeem,
        nav_addr_refund,
        secret_hash,
        lock_value,
        blinding_key,
    )
    ci_from.importBlsctScript(params, chain_height_before_submit)

    # Send NAV_ITX_IMPORT to bidder so they can import the HTLC script
    # and have tx_data_funded available to create the ITx redeem txn.
    nav_itx_import_payload = _build_nav_htlc_import_payload(
        MessageTypes.NAV_ITX_IMPORT, bid_id, blinding_key, lock_value,
        nav_addr_redeem, nav_addr_refund, chain_height_before_submit, txn_funded,
    )
    sc.sendMessage(
        offer.addr_from, bid.bid_addr, nav_itx_import_payload,
        sc.SMSG_SECONDS_IN_HOUR * 2, use_cursor,
        message_nets=bid.message_nets,
        payload_version=offer.smsg_payload_version,
    )
    sc.log.info(f"Sent NAV_ITX_IMPORT to bidder for bid {sc.log.id(bid_id)}")

# [processBidAccept / process_nav_itx_import]
# Side: Bidder
# Call Graph: processMsg[BID_ACCEPT] -> processBidAccept
#             processMsg[NAV_ITX_IMPORT] -> process_nav_itx_import
def import_nav_itx_and_rescan_nav_chain(sc, bid_id, bid) -> None:
    if bid.nav_itx_import_info is None:
        return
    _, blinding_key, lock_value, nav_addr_redeem, nav_addr_refund, rescan_from, tx_data_funded_bytes = _parse_nav_htlc_import_msg(bid.nav_itx_import_info)
    secret_hash = atomic_swap_1.extractScriptSecretHash(bid.initiate_tx.script)
    params = _build_import_blsct_script_params(
        nav_addr_redeem, nav_addr_refund, secret_hash, lock_value, blinding_key,
    )
    ci_nav = sc.ci(Coins.NAV)
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
    _, blinding_key, lock_value, nav_addr_redeem, nav_addr_refund, rescan_from, tx_data_funded_bytes = _parse_nav_htlc_import_msg(bid.nav_ptx_import_info)
    secret_hash = atomic_swap_1.extractScriptSecretHash(bid.initiate_tx.script)
    params = _build_import_blsct_script_params(
        nav_addr_redeem, nav_addr_refund, secret_hash, lock_value, blinding_key,
    )
    ci_nav = sc.ci(Coins.NAV)
    ci_nav.importBlsctScript(params, rescan_from)
    sc.log.info(f"Imported NAV PTX HTLC script for bid {sc.log.id(bid_id)}")
    ensure(tx_data_funded_bytes is not None, "NAV_PTX_IMPORT missing tx_data_funded")
    fake_script = ci_nav.createFakeNonNavHTLCScript(secret_hash, lock_value)
    bid.participate_tx.script = fake_script
    bid.participate_tx.tx_data_funded = tx_data_funded_bytes
    bid.nav_ptx_import_info = None
    return True

# [MessageHandler: NAV_ITX_IMPORT]
# Side: Bidder
# Call Graph: update -> processMsg[NAV_ITX_IMPORT]
def process_nav_itx_import(sc, msg) -> None:
    msg_bytes = sc.getSmsgMsgBytes(msg)
    bid_id = msg_bytes[:28]

    # If bid_id is in swaps_in_progress, update the object there
    # and save to the db. Otherwise, modify the bid object in the db
    # so that later the bid in db will be added to swaps_in_progress
    if bid_id in sc.swaps_in_progress:
        bid = sc.swaps_in_progress[bid_id][0]
    else:
        bid = sc.getBid(bid_id)

    bid.nav_itx_import_info = msg_bytes
    # NAV_ITX_IMPORT may arrive after BID_ACCEPT; if initiate_tx already set, process immediately
    # rather than waiting for the next processBidAccept drain.
    if bid.initiate_tx is not None:
        import_nav_itx_and_rescan_nav_chain(sc, bid_id, bid)
    sc.saveBid(bid_id, bid)

# [MessageHandler: NAV_PTX_IMPORT]
# Side: Offerer
# Call Graph: update -> processMsg[NAV_PTX_IMPORT]
def process_nav_ptx_import(sc, msg) -> None:
    msg_bytes = sc.getSmsgMsgBytes(msg)
    bid_id = msg_bytes[:28]
    # PTX import always arrives after the offerer accepted and the ITX confirmed,
    # so the bid is already in swaps_in_progress; mutate that live object so
    # checkBidState (which reads the in-memory bid) sees nav_ptx_import_info.
    bid = sc.swaps_in_progress[bid_id][0]
    bid.nav_ptx_import_info = msg_bytes
    sc.saveBid(bid_id, bid)

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

# [checkBidState / SWAP_INITIATED]
# Side: Offerer
# Call Graph: update -> checkBidState[SWAP_INITIATED]
def update_ptx_outid_and_state(sc, bid_id, bid, coin_to, ci_to, found) -> bool:
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
        bid.participate_tx.chain_height = sc.setLastHeightCheckedStart(coin_to, found["height"])
        if bid.participate_tx.state is None or bid.participate_tx.state < TxStates.TX_SENT:
            bid.setPTxState(TxStates.TX_SENT)
        save_bid = True
    return save_bid
