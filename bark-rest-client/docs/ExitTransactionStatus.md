# ExitTransactionStatus

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**history** | Option<[**Vec<models::ExitState>**](ExitState.md)> | The history of each state the exit transaction has gone through | [optional]
**state** | [**models::ExitState**](ExitState.md) | The current state of the exit transaction | 
**transactions** | Option<[**Vec<models::ExitTransactionPackage>**](ExitTransactionPackage.md)> | Each exit transaction package required for the unilateral exit | [optional]
**vtxo_id** | **String** | The ID of the VTXO that is being unilaterally exited | 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


