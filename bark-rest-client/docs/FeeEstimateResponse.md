# FeeEstimateResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**fee_sat** | **i64** | The fee portion (in satoshis) | 
**gross_amount_sat** | **i64** | The total amount including fees (in satoshis) | 
**net_amount_sat** | **i64** | The amount excluding fees (in satoshis). For sends, this is the amount the recipient receives. For receives, this is the amount the user gets. | 
**vtxos_spent** | **Vec<String>** | The VTXOs that would be spent for this operation | 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


