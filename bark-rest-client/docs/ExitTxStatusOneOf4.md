# ExitTxStatusOneOf4

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**block** | [**models::BlockRef**](BlockRef.md) |  | 
**child_txid** | Option<**String**> | `null` when the exit transaction confirmed without a CPFP child. A child can still be unconfirmed, `origin` tells. | [optional]
**origin** | [**models::ExitTxOrigin**](ExitTxOrigin.md) |  | 
**r#type** | **Type** |  (enum: confirmed) | 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


