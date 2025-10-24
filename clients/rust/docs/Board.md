# Board

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**funding_txid** | **String** | The [Txid] of the funding-transaction. This is the transaction that has to be confirmed onchain for the board to succeed. | 
**vtxos** | [**Vec<models::VtxoInfo>**](VtxoInfo.md) | The info for each [ark::Vtxo] that was created in this board.  Currently, this is always a vector of length 1 | 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


