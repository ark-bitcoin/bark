# PpmExpiryFeeEntry

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**expiry_blocks_threshold** | **i32** | A threshold for the number of blocks until a VTXO expires for the `ppm` amount to apply. As an example, if this value is set to 50 and a VTXO expires in 60 blocks, this [PpmExpiryFeeEntry] will be used to calculate the fee unless another entry exists with an `expiry_blocks_threshold` with a value between 51 and 60 (inclusive). | 
**ppm** | **i64** | PPM (parts per million) fee rate to apply for this expiry period. | 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


