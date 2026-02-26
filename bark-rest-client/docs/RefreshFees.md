# RefreshFees

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**base_fee_sat** | **i64** | A fee applied to every transaction regardless of value. | 
**ppm_expiry_table** | [**Vec<models::PpmExpiryFeeEntry>**](PpmExpiryFeeEntry.md) | A table mapping how soon a VTXO will expire to a PPM (parts per million) fee rate. The table should be sorted by each `expiry_blocks_threshold` value in ascending order. | 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


