# PresignedExits

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**exits** | [**Vec<models::PresignedExit>**](PresignedExit.md) | One entry per requested VTXO, in request order. | 
**waves** | [**Vec<models::PresignedWave>**](PresignedWave.md) | The broadcast plan. Confirmed transactions are omitted, relayed ones are listed in `in_mempool`, and a package shared by several exits appears once, under the first exit that references it. | 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


