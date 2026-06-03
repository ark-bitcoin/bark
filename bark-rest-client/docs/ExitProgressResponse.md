# ExitProgressResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**claimable_height** | Option<**i32**> | Block height at which all exit outputs will be spendable | [optional]
**done** | **bool** | Whether all transactions have been confirmed | 
**error** | Option<[**models::ExitError**](ExitError.md)> | Top-level error that prevented progress from running cleanly this round. Per-exit problems live on each `ExitProgressStatus`; this slot is for failures that can't be attributed to a specific VTXO (e.g. the chain source becoming unavailable, or the exit manager failing to refresh its view of pending transactions). | [optional]
**exits** | [**Vec<models::ExitProgressStatus>**](ExitProgressStatus.md) | Status of each pending exit transaction | 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


