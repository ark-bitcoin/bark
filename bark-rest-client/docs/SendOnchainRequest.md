# SendOnchainRequest

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**amount_sat** | **i64** | The amount (in satoshis) to be received by `destination` onchain. Must be >= [P2TR_DUST](bitcoin_ext::P2TR_DUST). Server-configured fees laid out in [OffboardFees](crate::cli::OffboardFees) will be added on top of this amount. | 
**destination** | **String** | The destination Bitcoin address | 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


