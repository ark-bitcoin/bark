# Balance

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**claimable_lightning_receive_sat** | **i64** | Sats in HTLC VTXOs of an incoming Lightning payment whose preimage has been revealed but which have not been swapped for spendable VTXOs yet. A payment that can still be cancelled is not counted. | 
**needs_refresh_sat** | **i64** | Sats in VTXOs that can no longer be sent in an arkoor payment because they have expired or their exit depth has reached the server's limit. They can still be offboarded, exited or refreshed, but are not part of `spendable_sat` until maintenance has refreshed them. | 
**pending_arkoor_send_sat** | **i64** | Sats locked in an outgoing arkoor payment that has not completed yet: the whole input amount, until the send finalizes and the change comes back as spendable. | 
**pending_board_sat** | **i64** | Sats in board transactions that are waiting for sufficient on-chain confirmations before becoming spendable. | 
**pending_exit_sat** | **i64** | Sats held in VTXOs whose unilateral exit has committed on-chain but which haven't yet been drained to the onchain wallet: their state is [`VtxoStateInfo::Exited`] and their exit has not reached [`ExitStateKind::Claimed`]. | 
**pending_in_round_sat** | **i64** | Sats locked in VTXOs forfeited for a round that has not yet completed. | 
**pending_lightning_send_sat** | **i64** | Sats locked in an outgoing Lightning payment that has not yet settled. | 
**pending_offboard_sat** | **i64** | Sats locked in an offboard whose transaction has not been broadcast yet, including any change that comes back. Once the transaction is on the network the sats belong to the on-chain wallet. | 
**spendable_sat** | **i64** | Sats that are immediately spendable, either in-round or out-of-round. | 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


