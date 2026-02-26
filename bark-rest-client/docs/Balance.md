# Balance

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**claimable_lightning_receive_sat** | **i64** | Sats from an incoming Lightning payment that can be claimed but have not yet been swept into a spendable VTXO. | 
**pending_board_sat** | **i64** | Sats in board transactions that are waiting for sufficient on-chain confirmations before becoming spendable. | 
**pending_exit_sat** | Option<**i64**> | Sats in VTXOs undergoing an emergency exit back on-chain. `null` if the exit subsystem is unavailable. | [optional]
**pending_in_round_sat** | **i64** | Sats locked in VTXOs forfeited for a round that has not yet completed. | 
**pending_lightning_send_sat** | **i64** | Sats locked in an outgoing Lightning payment that has not yet settled. | 
**spendable_sat** | **i64** | Sats that are immediately spendable, either in-round or out-of-round. | 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


