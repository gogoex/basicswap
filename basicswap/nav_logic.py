# -*- coding: utf-8 -*-

# Copyright (c) 2025 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import basicswap.protocols.atomic_swap_1 as atomic_swap_1
from basicswap.basicswap_util import ActionTypes, MessageTypes, TxStates, TxTypes
from basicswap.chainparams import Coins
from basicswap.util import b2i, ensure
from basicswap.util.address import decodeWif


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

# [acceptBid]
def create_initiate_txn(sc, bid_id, bid, offer, ci_from, lock_value, secret_hash, bid_date, use_cursor):
    ensure(bid.nav_redeem_addr is not None, "NAV ITX redeem address not set; bidder must send nav_redeem_addr in BID")
    nav_addr_redeem = bid.nav_redeem_addr
    nav_addr_refund = sc.getReceiveAddressFromPool(Coins.NAV, bid_id, TxTypes.ITX_REFUND, use_cursor)
    seller_privkey = sc.getContractPrivkey(bid_date, bid.contract_count)
    blinding_key = ci_from.deriveBlindingKey(seller_privkey, bid.buyer_contract_pubkey)

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
    sc.saveBid(bid_id, bidi
