# ExitTxStatusOneOf4

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**block** | [**models::BlockRef**](BlockRef.md) | The block that confirmed the exit transaction. | 
**child_txid** | **String** | **Deprecated**: confirmed exit transactions no longer track a CPFP child. This field is always an empty string and will be removed in a future release. | 
**origin** | [**models::ExitTxOrigin**](ExitTxOrigin.md) | **Deprecated**: use `block`. This field is always a `block` origin confirmed in `block`, kept for backwards compatibility, and will be removed in a future release. | 
**r#type** | **Type** |  (enum: confirmed) | 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


