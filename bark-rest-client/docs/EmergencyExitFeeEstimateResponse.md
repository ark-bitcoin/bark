# EmergencyExitFeeEstimateResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**claim_fee_sat** | **i64** | The fee for the single batched transaction that drains the matured exit outputs (in satoshis). Paid later out of the recovered value. | 
**exit_broadcast_fee_sat** | **i64** | The CPFP fees to broadcast every not-yet-confirmed exit transaction (in satoshis). Paid now from confirmed on-chain funds. | 
**fee_rate_sat_per_vb** | **i64** | The fee rate the exit-broadcast leg was priced at (sat/vB). Unless an explicit fee rate was supplied, the claim leg is priced separately at the chain's `regular` rate. | 
**fundable** | **bool** | Whether the wallet's current on-chain balance covers the full serial exit-broadcast walk. | 
**total_fee_sat** | **i64** | The sum of the broadcast and claim fees (in satoshis). | 
**txs_to_broadcast** | **i32** | The number of exit transactions that still need to be broadcast and CPFP-bumped. | 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


