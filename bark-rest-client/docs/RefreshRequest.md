# RefreshRequest

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**vtxos** | **Vec<String>** | List of VTXO IDs to refresh. The sum of the VTXOs being refreshed must be >= [P2TR_DUST](bitcoin_ext::P2TR_DUST). Keep in mind that fees set out in [RefreshFees](crate::cli::RefreshFees) will be deducted from the newly created VTXO, this value must also be >= [P2TR_DUST](bitcoin_ext::P2TR_DUST). | 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


