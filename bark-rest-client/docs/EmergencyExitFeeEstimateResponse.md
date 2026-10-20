# EmergencyExitFeeEstimateResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**claim_fee_sat** | **i64** | The fee for the single batched transaction that drains the matured exit outputs (in satoshis). Paid later out of the recovered value. | 
**exit_broadcast_fee_sat** | **i64** | The CPFP fees to broadcast every not-yet-confirmed exit transaction (in satoshis), including the fee margin. Paid from confirmed on-chain funds; this is the on-chain balance to fund the exit with at the chosen margin. | 
**fee_rate_sat_per_vb** | **f64** | The fee rate the exit-broadcast leg was priced at (sat/vB), before the fee margin. Unless an explicit fee rate was supplied, the claim leg is priced separately at the chain's `regular` rate. | 
**fundable** | **bool** | Whether the wallet's on-chain balance covers `exit_broadcast_fee_sat`.  **Deprecated**: the estimate is a funding target and no longer consults the wallet's funds. Compare `exit_broadcast_fee_sat` against the on-chain balance instead. This field is still populated from the last synced on-chain balance for backwards compatibility and will be removed in a future release. | 
**total_fee_sat** | **i64** | The sum of the broadcast and claim fees (in satoshis). | 
**txs_to_broadcast** | **i32** | The number of exit transactions that still need to be broadcast and CPFP-bumped. | 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


