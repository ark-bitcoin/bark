# EmergencyExitFeeEstimateQuery

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**destination** | Option<**String**> | The destination address for the claim. Only affects the claim-fee weight; when omitted a placeholder of the configured network is used. | [optional]
**fee_rate_sat_per_vb** | Option<**i64**> | The fee rate to price the estimate at, in sat/vB. Applied to both the broadcast and claim legs. When omitted, the broadcast leg uses the current `fast` rate and the claim leg the `regular` rate. | [optional]
**vtxo_ids** | Option<**String**> | Comma-separated VTXO ids to estimate the exit for. When omitted, every spendable VTXO in the wallet is used (i.e. exit the entire wallet). | [optional]

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


