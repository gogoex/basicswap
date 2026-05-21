# -*- coding: utf-8 -*-

# Copyright (c) 2025 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import datetime as dt

import basicswap.protocols.atomic_swap_1 as atomic_swap_1
from basicswap.basicswap_util import ActionTypes, BidStates, EventLogTypes, MessageTypes, TxStates, TxTypes
from basicswap.chainparams import Coins
from basicswap.db import Concepts
from basicswap.util import b2i, ensure
from basicswap.util.address import decodeWif


# [createRefundTxn]
def build_nav_refund_prevout(sc, bid, ci, txn, secret_hash, addr_refund_out) -> dict:
    # Decodes funded tx via decodeblsctrawtransaction, finds the HTLC output matching secret_hash,
    # returns {"outid", "amount", "gamma"}. No spending_key — caller must derive and set it.
    prevout = ci.getPrevOutInfoFromOffChainTxn(txn, secret_hash)

    bid_date = dt.datetime.fromtimestamp(bid.created_at).date()
    local_privkey = sc.getContractPrivkey(bid_date, bid.contract_count)
    ecdh_cpty_pubkey = bid.bidder_contract_pubkey if bid.was_received else bid.offerer_contract_pubkey
    blinding_key_int = ci.deriveBlindingKey(local_privkey, ecdh_cpty_pubkey)
    prevout["spending_key"] = ci.deriveSpendingKey(
        f"{blinding_key_int:064x}", addr_refund_out
    )
    return prevout

# [createRedeemTxn]
def build_nav_redeem_prevout(sc, bid, ci, nav_txn, privkey, txn_script, is_ptx) -> dict:
    secret_hash = atomic_swap_1.extractScriptSecretHash(txn_script)
    tx_data_funded = nav_txn.tx_data_funded

    # Try to reload tx_data_funded from DB if lost from memory (e.g. after restart)
    if tx_data_funded is None:
        sc.log.warning(f"createRedeemTxn: {'PTx' if is_ptx else 'ITx'} tx_data_funded not in memory for bid {sc.log.id(bid.bid_id)}, reloading from DB")
        db_bid = sc.getBid(bid.bid_id)
        db_tx = db_bid.participate_tx if (db_bid and is_ptx) else (db_bid.initiate_tx if db_bid else None)
        if db_tx:
            tx_data_funded = db_tx.tx_data_funded
        else:
            raise ValueError(f"NAV {'PTX' if is_ptx else 'ITX'} tx_data_funded not available for bid {bid.bid_id.hex()}")

    prevout = ci.getPrevOutInfoFromOffChainTxn(tx_data_funded.hex(), secret_hash)
    if nav_txn.txid is not None:
        # outid has been stored as txid
        prevout["outid"] = nav_txn.txid.hex()

    ecdh_pubkey = bid.bidder_contract_pubkey if bid.was_received else bid.offerer_contract_pubkey
    blinding_key_int = ci.deriveBlindingKey(privkey, ecdh_pubkey)
    prevout["spending_key"] = ci.deriveSpendingKey(
        f"{blinding_key_int:064x}", bid.nav_redeem_addr
    )
    return prevout

# [Misc]
def confirm_wallet_minimum_balance(sc, c) -> None:
    ci = sc.ci(c)
    try:
        fee_rate, _ = ci.get_fee_rate()
        min_bal = (fee_rate * ci.getHTLCSpendTxVSize()) / 1000 * 1.3
        balance = ci.getWalletInfo().get("balance", 0.0)
        if balance < min_bal:
            raise ValueError(
                f"Navio wallet balance ({balance:.8f} NAV) too low to pay redeem fees. "
                f"Minimum {min_bal:.8f} NAV required."
            )
    except ValueError:
        raise
    except Exception as e:
        sc.log.warning(f"could not check NAV balance: {e}")

# [createParticipateTxn]
def create_nav_ptx(sc, bid_id, bid, offer, ci) -> tuple:
    # Extract secret hash from ITX script and use offerer's nav address as redeem address and bidder's nav address as refund address
    secret_hash = atomic_swap_1.extractScriptSecretHash(bid.initiate_tx.script)
    nav_addr_redeem = bid.nav_redeem_addr
    ensure(nav_addr_redeem is not None, "NAV redeem address not set; server must send nav_redeem_addr in BID_ACCEPT")
    nav_addr_refund = sc.getReceiveAddressFromPool(Coins.NAV, bid_id, TxTypes.PTX_REFUND, None)

    # Derive blinding key via ECDH (bidder_privkey, offerer_pubkey)
    bid_date = dt.datetime.fromtimestamp(bid.created_at).date()
    bidder_privkey = sc.getContractPrivkey(bid_date, bid.contract_count)
    lock_value = ci.getParticipateLockValue(offer)
    blinding_key = ci.deriveBlindingKey(bidder_privkey, bid.offerer_contract_pubkey)

    # Create funded PTX and PTX refund txn
    txn_funded, vout_index = ci.createInitiateTxn(
        nav_addr_redeem, nav_addr_refund, secret_hash, lock_value, blinding_key, bid.amount_to,
    )
    participate_script = ci.createFakeNonNavHTLCScript(secret_hash, lock_value)
    refund_txn = sc.createRefundTxn(
        Coins.NAV, txn_funded, offer, bid, participate_script,
        addr_refund_out=nav_addr_refund, secret_hash=secret_hash, tx_type=TxTypes.PTX_REFUND,
    )
    bid.participate_txn_refund = bytes.fromhex(refund_txn)

    # Sign PTX and get the txid
    txn_signed = ci.signBlsct(txn_funded)
    txjs = ci.rpc("decoderawtransaction", [txn_signed])
    txid = txjs["txid"]

    # Import HTLC script so wallet tracks the PTX output
    params = {
        "type": "atomic_swap",
        "address_a": nav_addr_redeem,
        "address_b": nav_addr_refund,
        "hash": secret_hash.hex(),
        "locktime": lock_value,
        "blinding_key": f"{blinding_key:064x}",
    }
    ci.importBlsctScript(params, None)

    # Build NAV_PTX_IMPORT payload to send to offerer
    chain_height = ci.getChainHeight()
    addr_a_bytes = nav_addr_redeem.encode()
    addr_b_bytes = nav_addr_refund.encode()
    blinding_key_bytes = blinding_key.to_bytes(32, "big")
    lock_value_bytes = lock_value.to_bytes(4, "big")
    chain_height_bytes = chain_height.to_bytes(4, "big")
    tx_data_bytes = bytes.fromhex(txn_funded)
    tx_data_len_bytes = len(tx_data_bytes).to_bytes(4, "big")
    nav_ptx_import_payload = (
        format(int(MessageTypes.NAV_PTX_IMPORT), "02x")
        + bid_id.hex()
        + blinding_key_bytes.hex()
        + lock_value_bytes.hex()
        + format(len(addr_a_bytes), "02x")
        + addr_a_bytes.hex()
        + format(len(addr_b_bytes), "02x")
        + addr_b_bytes.hex()
        + chain_height_bytes.hex()
        + tx_data_len_bytes.hex()
        + tx_data_bytes.hex()
    )

    # Update bid participate_tx fields
    sc.addParticipateTxn(bid_id, bid, Coins.NAV, txid, vout_index, chain_height)
    bid.participate_tx.script = participate_script
    bid.participate_tx.tx_data = bytes.fromhex(txn_signed)
    bid.participate_tx.tx_data_funded = bytes.fromhex(txn_funded)
    prevout_info = ci.getPrevOutInfoFromOffChainTxn(txn_funded, secret_hash)
    bid.participate_tx.txid = bytes.fromhex(prevout_info["outid"])

    return txn_signed, nav_ptx_import_payload

# [acceptBid]
def create_initiate_txn(sc, bid_id, bid, offer, ci_from, lock_value, secret_hash, bid_date, use_cursor):
    ensure(bid.nav_redeem_addr is not None, "NAV ITX redeem address not set; bidder must send nav_redeem_addr in BID")
    nav_addr_redeem = bid.nav_redeem_addr
    nav_addr_refund = sc.getReceiveAddressFromPool(Coins.NAV, bid_id, TxTypes.ITX_REFUND, use_cursor)
    seller_privkey = sc.getContractPrivkey(bid_date, bid.contract_count)
    blinding_key = ci_from.deriveBlindingKey(seller_privkey, bid.bidder_contract_pubkey)

    txn, lock_tx_vout = ci_from.createInitiateTxn(
        nav_addr_redeem, nav_addr_refund, secret_hash, lock_value, blinding_key, bid.amount,
    )

    return txn, lock_tx_vout, nav_addr_redeem, nav_addr_refund, blinding_key

# [Misc]
def derive_bls_key(sc, coin_type, evkey, key_path_base) -> bytes:
    BLS_GROUP_ORDER = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001
    parent_path = key_path_base.rpartition("/")[0]
    # TODO NAV: use 1 upon creating a pr
    nonce = 2
    while True:
        key_path = "{}/{}".format(parent_path, nonce)
        extkey = sc.callcoinrpc(Coins.PART, "extkey", ["info", evkey, key_path])["key_info"]["result"]
        privkey = decodeWif(
            sc.callcoinrpc(Coins.PART, "extkey", ["info", extkey])["key_info"]["privkey"]
        )
        i = b2i(privkey) % BLS_GROUP_ORDER
        if i != 0:
            return i.to_bytes(32, "big")
        nonce += 1
        if nonce > 0x7FFFFFFF:
            raise ValueError("deriveBLSKey failed")

# [checkBidState / SWAP_INITIATED]
def detect_nav_itx_refund(sc, bid_id, bid, ci_from) -> bool:
    # NAV ITX may be refunded while waiting for PTX confirmation.
    # BLSCT outputs have no visible address, so check via isHTLCTxnSpent (listblsctunspent).
    if (
        bid.initiate_tx is not None
        and bid.getITxState() in (TxStates.TX_SENT, TxStates.TX_CONFIRMED)
        and ci_from.isHTLCTxnSpent(bid.initiate_tx.script)
    ):
        sc.log.info(f"NAV ITx spent (refunded) in SWAP_INITIATED for bid {sc.log.id(bid_id)}, marking TX_REFUNDED")
        bid.setITxState(TxStates.TX_REFUNDED)
        return True
    return False

# [checkBidState / SWAP_PARTICIPATING]
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

# [processBidAccept]
def import_nav_itx_and_rescan_nav_chain(sc, bid_id, bid) -> None:
    if bid_id not in sc._pending_nav_itx_imports:
        return

    # Import NAV Itx
    sc.log.info(f"processBidAccept: draining stashed NAV_ITX_IMPORT for bid {sc.log.id(bid_id)}")
    stash = sc._pending_nav_itx_imports.pop(bid_id)
    secret_hash = atomic_swap_1.extractScriptSecretHash(bid.initiate_tx.script)
    params = {
        "type": "atomic_swap",
        "address_a": stash["nav_addr_redeem"],
        "address_b": stash["nav_addr_refund"],
        "hash": secret_hash.hex(),
        "locktime": stash["lock_value"],
        "blinding_key": f"{stash['blinding_key']:064x}",
    }
    ci_nav = sc.ci(Coins.NAV)
    rescan_from = stash["rescan_from"]
    ci_nav.importBlsctScript(params, rescan_from)
    sc.log.info(f"processBidAccept: imported NAV ITX HTLC script for bid {sc.log.id(bid_id)}")

    bid.initiate_tx.script = ci_nav.createFakeNonNavHTLCScript(secret_hash, stash["lock_value"])

    # Rescan the nav chain from the height where the Itx is first confirmed
    try:
        chain_height = ci_nav.rpc("getblockchaininfo")["blocks"]
        rescan_from = min(rescan_from, chain_height)
    except Exception as e:
        sc.log.warning(f"processBidAccept: could not clamp rescan_from: {e}")
    sc.log.info(f"processBidAccept: rescanning from height {rescan_from} to find ITX UTXO")
    ci_nav.rpc_wallet("rescanblockchain", [rescan_from])
    sc.log.info(f"processBidAccept: rescan complete")

    tx_data_funded_bytes = stash["tx_data_funded_bytes"]
    if tx_data_funded_bytes is not None:
        bid.initiate_tx.tx_data_funded = tx_data_funded_bytes
        sc.saveBid(bid_id, bid)
        sc.log.info(f"processBidAccept: persisted NAV ITX tx_data_funded for bid {sc.log.id(bid_id)}")

# [checkBidState]
def is_initiate_txn_on_chain(sc, bid_id, bid, ci_from) -> dict:
    # Search by secret hash via listblsctunspent; BLSCT outputs have no visible address
    secret_hash = atomic_swap_1.extractScriptSecretHash(bid.initiate_tx.script)
    locktime = ci_from.extractHTLCLockVal(bid.initiate_tx.script, is_nav=False)
    return ci_from.getNavLockTxHeight(
        bid.initiate_tx.txid,
        secret_hash.hex(),
        bid.amount,
        bid.chain_a_height_start,
        lock_val=locktime,
    )

# [checkBidState]
def is_nav_itx_refunded(sc, bid_id, bid, ci_from) -> bool:
    # ITX was previously confirmed but UTXO gone — spent before re-detection, likely refunded
    if (
        bid.getITxState() == TxStates.TX_SENT
        and bid.initiate_tx.conf is not None
        and bid.initiate_tx.conf >= 1
        and ci_from.isHTLCTxnSpent(bid.initiate_tx.script)
    ):
        bid.setITxState(TxStates.TX_REFUNDED)
        bid.setState(BidStates.SWAP_COMPLETED)
        sc.saveBid(bid_id, bid)
        return True
    return False

# [acceptBid]
def import_itx_and_send_payload_msg_to_bidder(sc, bid_id, bid, offer, ci_from, nav_addr_redeem, nav_addr_refund, secret_hash, lock_value, blinding_key, txn_funded, chain_height_before_submit, use_cursor):
    # Import HTLC script so wallet tracks the output after tx aggregation (txid changes when mined).
    params = {
        "type": "atomic_swap",
        "address_a": nav_addr_redeem,
        "address_b": nav_addr_refund,
        "hash": secret_hash.hex(),
        "locktime": lock_value,
        "blinding_key": f"{blinding_key:064x}",
    }
    ci_from.importBlsctScript(params, chain_height_before_submit)

    # Send NAV_ITX_IMPORT to bidder so they can import the HTLC script
    # and have tx_data_funded available to create the ITx redeem txn.
    addr_a_bytes = nav_addr_redeem.encode()
    addr_b_bytes = nav_addr_refund.encode()
    blinding_key_bytes = blinding_key.to_bytes(32, "big")
    lock_value_bytes = lock_value.to_bytes(4, "big")
    chain_height_bytes = chain_height_before_submit.to_bytes(4, "big")
    tx_data_bytes = bytes.fromhex(txn_funded)
    tx_data_len_bytes = len(tx_data_bytes).to_bytes(4, "big")
    nav_itx_import_payload = (
        format(int(MessageTypes.NAV_ITX_IMPORT), "02x")
        + bid_id.hex()
        + blinding_key_bytes.hex()
        + lock_value_bytes.hex()
        + format(len(addr_a_bytes), "02x")
        + addr_a_bytes.hex()
        + format(len(addr_b_bytes), "02x")
        + addr_b_bytes.hex()
        + chain_height_bytes.hex()
        + tx_data_len_bytes.hex()
        + tx_data_bytes.hex()
    )
    sc.sendMessage(
        offer.addr_from, bid.bid_addr, nav_itx_import_payload,
        sc.SMSG_SECONDS_IN_HOUR * 2, use_cursor,
        message_nets=bid.message_nets,
        payload_version=offer.smsg_payload_version,
    )
    sc.log.info(f"Sent NAV_ITX_IMPORT to bidder for bid {sc.log.id(bid_id)}")

# [MessageHandler]
def process_nav_itx_import(sc, msg) -> None:
    """Receive NAV ITX BLSCT HTLC params from offerer (bid acceptor).
    Imports the HTLC script into the bidder's NAV wallet so getLockTxHeight
    can find the ITX via listblsctunspent, and stores tx_data_funded for
    createRedeemTxn to use when the bidder redeems the NAV ITx."""
    sc.log.debug(f"processNavItxImport from {msg['from']}")
    msg_bytes = sc.getSmsgMsgBytes(msg)
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
    # tx_data_funded: raw funded NAV ITX for the bidder to use in createRedeemTxn
    if offset < len(msg_bytes):
        tx_data_len = int.from_bytes(msg_bytes[offset: offset + 4], "big")
        offset += 4
        tx_data_funded_bytes = msg_bytes[offset: offset + tx_data_len]
    else:
        tx_data_funded_bytes = None

    sc.log.info(f"processNavItxImport: bid {sc.log.id(bid_id)}, {nav_addr_redeem=}, {lock_value=}")
    if bid_id not in sc.swaps_in_progress:
        # BID_ACCEPT may arrive slightly after NAV_ITX_IMPORT (SMSG ordering not guaranteed).
        # Stash the data; processBidAccept will drain it once the bid is in-progress.
        sc.log.warning(f"processNavItxImport: bid {sc.log.id(bid_id)} not yet in progress — stashing for later")
        sc._pending_nav_itx_imports[bid_id] = {
            "nav_addr_redeem": nav_addr_redeem,
            "nav_addr_refund": nav_addr_refund,
            "blinding_key": blinding_key,
            "lock_value": lock_value,
            "rescan_from": rescan_from,
            "tx_data_funded_bytes": tx_data_funded_bytes,
        }
        return

    bid = sc.swaps_in_progress[bid_id][0]
    if bid.was_received:
        sc.log.warning(f"processNavItxImport: bid {sc.log.id(bid_id)} was received (expected sent bid)")
        return

    if bid.initiate_tx is None:
        sc.log.warning(f"processNavItxImport: bid {sc.log.id(bid_id)} has no initiate_tx yet")
        return

    secret_hash = atomic_swap_1.extractScriptSecretHash(bid.initiate_tx.script)
    params = {
        "type": "atomic_swap",
        "address_a": nav_addr_redeem,
        "address_b": nav_addr_refund,
        "hash": secret_hash.hex(),
        "locktime": lock_value,
        "blinding_key": f"{blinding_key:064x}",
    }
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
            sc.log.warning(f"processNavItxImport: could not clamp rescan_from: {e}")
        sc.log.info(f"processNavItxImport: rescanning from height {rescan_from} to find ITX UTXO")
        ci_nav.rpc_wallet("rescanblockchain", [rescan_from])
        sc.log.info(f"processNavItxImport: rescan complete")

    ensure(tx_data_funded_bytes is not None, "NAV_ITX_IMPORT missing tx_data_funded")
    ensure(bid.initiate_tx.tx_data_funded is None, "NAV ITX tx_data_funded already set")
    bid.initiate_tx.tx_data_funded = tx_data_funded_bytes
    sc.saveBid(bid_id, bid)
    sc.log.info(f"Persisted NAV ITX tx_data_funded to DB for bid {sc.log.id(bid_id)}")

# [MessageHandler]
def process_nav_ptx_import(sc, msg) -> None:
    """Receive NAV PTX BLSCT HTLC params from bidder.
    Imports the HTLC script into the offer creator's NAV wallet so
    getLockTxHeight can find the PTX via listblsctunspent."""
    sc.log.debug(f"processNavPtxImport from {msg['from']}")
    msg_bytes = sc.getSmsgMsgBytes(msg)
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
    # tx_data_funded: raw funded NAV PTX for the server to use in createRedeemTxn
    if offset < len(msg_bytes):
        tx_data_len = int.from_bytes(msg_bytes[offset: offset + 4], "big")
        offset += 4
        tx_data_funded_bytes = msg_bytes[offset: offset + tx_data_len]
    else:
        tx_data_funded_bytes = None

    sc.log.info(f"processNavPtxImport: bid {sc.log.id(bid_id)}, {nav_addr_redeem=}, {lock_value=}")
    if bid_id not in sc.swaps_in_progress:
        sc.log.warning(f"processNavPtxImport: bid {sc.log.id(bid_id)} not in progress")
        return

    bid = sc.swaps_in_progress[bid_id][0]
    if not bid.was_received:
        sc.log.warning(f"processNavPtxImport: bid {sc.log.id(bid_id)} not received bid")
        return

    if bid.initiate_tx is None:
        sc.log.warning(f"processNavPtxImport: bid {sc.log.id(bid_id)} has no initiate_tx yet")
        return

    secret_hash = atomic_swap_1.extractScriptSecretHash(bid.initiate_tx.script)
    params = {
        "type": "atomic_swap",
        "address_a": nav_addr_redeem,
        "address_b": nav_addr_refund,
        "hash": secret_hash.hex(),
        "locktime": lock_value,
        "blinding_key": f"{blinding_key:064x}",
    }
    ci_nav = sc.ci(Coins.NAV)
    ci_nav.importBlsctScript(params, rescan_from)
    sc.log.info(f"Imported NAV PTX HTLC script for bid {sc.log.id(bid_id)}")
    ensure(tx_data_funded_bytes is not None, "NAV_PTX_IMPORT missing tx_data_funded")

    fake_script = ci_nav.createFakeNonNavHTLCScript(secret_hash, lock_value)
    ci_nav.stashPtxOfferer(bid_id, fake_script, tx_data_funded_bytes)
    sc.log.info(f"Stashed NAV PTX script and tx_data_funded for bid {sc.log.id(bid_id)}")

# [MessageHandler]
def process_nav_secret_reveal(sc, msg) -> None:
    msg_bytes = sc.getSmsgMsgBytes(msg)
    bid_id = msg_bytes[:28]
    secret = msg_bytes[28:60]

    sc.log.info(f"Received NAV secret reveal for bid {sc.log.id(bid_id)}")
    if bid_id not in sc.swaps_in_progress:
        sc.log.warning(f"processNavSecretReveal: bid {sc.log.id(bid_id)} not in progress")
        return

    bid = sc.swaps_in_progress[bid_id][0]
    if bid.was_received:
        sc.log.debug(f"processNavSecretReveal: offerer ignoring own reveal for bid {sc.log.id(bid_id)}")
        return

    bid.recovered_secret = secret
    # NAV PTx was spent by the offerer to reveal the secret — mark it redeemed
    if bid.participate_tx:
        bid.setPTxState(TxStates.TX_REDEEMED)
    delay = sc.get_short_delay_event_seconds()
    sc.log.info(f"Redeeming ITX for bid {sc.log.id(bid_id)} in {delay} seconds.")
    sc.createAction(delay, ActionTypes.REDEEM_ITX, bid_id)
    sc.saveBid(bid_id, bid)

# [participateToBid]
def publish_nav_ptx_and_send_ptx_import_msg(sc, bid_id, bid, offer, ci_to, txn, nav_ptx_import_payload) -> None:
    bid.participate_tx.not_published = False
    try:
        txid = ci_to.publishTx(bytes.fromhex(txn))
        sc.log.debug(f"Submitted participate tx {sc.logIDT(txid)} to {ci_to.coin_name()} chain for bid {sc.log.id(bid_id)}")
    except Exception as e:
        bid.participate_tx.not_published = True

    sc.sendMessage(bid.bid_addr, offer.addr_from, nav_ptx_import_payload, sc.SMSG_SECONDS_IN_HOUR * 2, None)
    sc.log.info(f"Sent NAV_PTX_IMPORT to offer creator for bid {sc.log.id(bid_id)}")
    if not bid.participate_tx.not_published:
        bid.setPTxState(TxStates.TX_SENT)
        sc.logEvent(Concepts.BID, bid.bid_id, EventLogTypes.PTX_PUBLISHED, "", None)

# [participateTxnConfirmed]
def send_nav_secret_reveal(sc, bid_id, bid, offer) -> None:
    # NAV uses BLSCT (private txns) so bidder can't observe the secret from the chain directly.
    # Offerer explicitly sends the secret to bidder so bidder can redeem the ITX (non-NAV side).
    bid_date = dt.datetime.fromtimestamp(bid.created_at).date()
    secret = sc.getContractSecret(bid_date, bid.contract_count)
    payload_hex = str.format("{:02x}", MessageTypes.NAV_SECRET_REVEAL) + bid_id.hex() + secret.hex()
    sc.sendMessage(offer.addr_from, bid.bid_addr, payload_hex, sc.SMSG_SECONDS_IN_HOUR, None)

# [checkBidState / SWAP_INITIATED]
def try_to_get_nav_ptx_info_from_chain(sc, bid_id, bid, ci_to, participate_txid):
    # Search by secret hash via listblsctunspent; BLSCT outputs have no visible address
    if bid.participate_tx is None or bid.participate_tx.script is None:
        return None
    secret_hash = atomic_swap_1.extractScriptSecretHash(bid.participate_tx.script)
    lock_val = ci_to.extractHTLCLockVal(bid.participate_tx.script, is_nav=False)
    return ci_to.getNavLockTxHeight(
        participate_txid,
        secret_hash.hex(),
        bid.amount_to,
        bid.chain_b_height_start,
        lock_val=lock_val,
    )

# [checkBidState / SWAP_INITIATED]
def try_to_publish_nav_ptx(sc, bid_id, bid, ci_to) -> bool:
    # if ptx info is not ready, retry in the next cycle
    if bid.was_sent and bid.participate_tx is None:
        return False
    # if ptx is already published, go to next
    if bid.participate_tx.not_published == False:
        return True

    try:
        txid = ci_to.publishTx(bid.participate_tx.tx_data)
        sc.log.debug(f"Submitted participate tx {sc.log.id(txid)} to NAV chain for bid {sc.log.id(bid_id)}")
        bid.participate_tx.not_published = False
        bid.setPTxState(TxStates.TX_SENT)
        sc.saveBid(bid_id, bid)
        return True

    except Exception as e:
        sc.log.warning(f"Failed to publish NAV PTX for bid {sc.log.id(bid_id)}: {e}")
        return False

# [checkBidState / SWAP_INITIATED]
def let_offerer_retrieve_nav_ptx(sc, bid_id, bid, ci_to) -> bool:
    # Offerer's participate_tx.script is None initially (set in participateToBid else: branch).
    # Offerer gets the script via NAV_PTX_IMPORT message stashed by process_nav_ptx_import ->
    # getPtxInfoOfferer retrieves it here.
    ptx_info = ci_to.getPtxInfoOfferer(bid_id)
    if ptx_info is None:
        return False
    bid.participate_tx.script = ptx_info["script"]
    bid.participate_tx.tx_data_funded = ptx_info["tx_data_funded"]
    sc.log.info(f"Applied stashed NAV PTX script for bid {sc.log.id(bid_id)}")
    return True

# [checkBidState / SWAP_INITIATED]
def update_ptx_outid_and_state(sc, bid_id, bid, coin_to, ci_to, found) -> bool:
    save_bid = False
    if bid.participate_tx.conf != found["depth"]:
        save_bid = True

    # NAV txid changes after aggregation — track by outid instead
    # Offerer: set txid from outid once known (bidder already has it from create_nav_ptx)
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
