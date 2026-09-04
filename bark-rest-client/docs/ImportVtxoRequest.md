# ImportVtxoRequest

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**allow_partial** | Option<**bool**> | Keep the VTXOs that import successfully even when another one in the request fails. The response lists the VTXOs that were kept.  Without it, a single failure discards the whole request. | [optional]
**gap_limit** | Option<**i32**> | How many consecutive unused key indices to scan for each VTXO's user pubkey. Overrides the wallet's configured gap limit. | [optional]
**skip_status_check** | Option<**bool**> | Import as spendable without asking the server for each VTXO's state.  Use it when you already know it's spendable or when the server can't be reached, as it can leave the wallet in an inconsistent state. | [optional]
**vtxos** | **Vec<String>** | Hex-encoded VTXOs to import | 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


