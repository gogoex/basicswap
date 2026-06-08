# -*- coding: utf-8 -*-

# Copyright (c) 2025 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from basicswap.basicswap_util import EventLogTypes, TxStates
from basicswap.db import Concepts


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

