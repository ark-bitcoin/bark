# PendingBoardInfo

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**funding_tx** | [**models::TransactionInfo**](TransactionInfo.md) | The funding transaction. This is the transaction that has to be confirmed onchain for the board to succeed. | 
**movement_id** | **i32** | The ID of the movement associated with this board. | 
**vtxos** | [**Vec<models::WalletVtxoInfo>**](WalletVtxoInfo.md) | The info for each [ark::Vtxo] that was created in this board.  Currently, this is always a vector of length 1 | 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


