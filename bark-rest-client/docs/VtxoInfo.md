# VtxoInfo

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**amount_sat** | **i64** | The value of this VTXO in sats. | 
**chain_anchor** | **String** | The on-chain outpoint that roots this VTXO, formatted as `txid:vout`. Typically an output of a round transaction or a board transaction. | 
**exit_delta** | **i32** |  | 
**exit_depth** | **i32** | The number of off-chain transactions in this VTXO. Each must be broadcast and confirmed on-chain in sequence during an emergency exit. | 
**expiry_height** | **i32** |  | 
**id** | **String** | Unique identifier for this VTXO, formatted as `txid:vout`. | 
**policy_type** | **String** | The spending policy that governs this VTXO. | 
**server_pubkey** | **String** | The Ark server's public key used to co-sign transactions involving this VTXO. | 
**user_pubkey** | **String** | The owner's public key. Only the holder of the corresponding private key can spend this VTXO. | 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


