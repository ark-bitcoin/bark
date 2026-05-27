# FeeInfo

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**fee_rate_sat_per_kvb** | **i64** | The effective fee rate of the transaction (including unconfirmed CPFP ancestors), in sats per kvB. `kvb` matches the unit used elsewhere in `bark-json` (e.g. `offboard_feerate_sat_per_kvb`). | 
**total_fee_sat** | **i64** | Sum of the transaction's own fee plus the fee of each of its unconfirmed ancestors. | 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


