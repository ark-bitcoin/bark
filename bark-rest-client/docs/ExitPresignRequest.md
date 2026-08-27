# ExitPresignRequest

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**fee_rate_sat_per_vb** | Option<**f64**> | The fee rate to sign the CPFP children at, in sat/vB (fractions allowed). When omitted, the current `fast` rate is used. | [optional]
**vtxos** | Option<**Vec<String>**> | The IDs of the VTXOs to presign exit chains for, in the order they will be broadcast. When omitted, every spendable VTXO in the wallet is used. | [optional]

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


