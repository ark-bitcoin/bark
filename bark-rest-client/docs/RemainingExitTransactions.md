# RemainingExitTransactions

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**exits** | [**std::collections::HashMap<String, Vec<String>>**](Vec.md) | The transactions each VTXO needs confirmed to be exited, in broadcast order. | 
**transactions** | [**Vec<models::TransactionInfo>**](TransactionInfo.md) | Every transaction referenced by `exits` exactly once, parents before children. | 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


