# PendingRoundInfo

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**funding_tx_hex** | Option<**String**> |  | [optional]
**funding_txid** | Option<**String**> | The round transaction id, if already assigned | 
**id** | **i32** | Unique identifier for the round | 
**participation** | [**models::RoundParticipationInfo**](RoundParticipationInfo.md) | the round participation details | 
**scheduled_height** | Option<**i32**> | The block height a delegated participation is scheduled for, if any | [optional]
**state** | [**models::RoundFlowState**](RoundFlowState.md) | Lifecycle phase of the participation | 
**status** | [**models::RoundStatus**](RoundStatus.md) | the current status of the round | 
**unlock_hash** | Option<**String**> |  | 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


