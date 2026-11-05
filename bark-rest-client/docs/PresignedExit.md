# PresignedExit

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**status** | [**models::PresignedExitStatus**](PresignedExitStatus.md) |  | 
**unsigned** | [**Vec<models::TransactionInfo>**](TransactionInfo.md) | The remaining tail of this exit's chain that could not be funded, in broadcast order; its first transaction spends this exit's last signed one. Empty when fully signed. | 
**vtxo_id** | **String** |  | 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


