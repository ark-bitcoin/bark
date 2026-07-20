# DelegatedRefreshRequest

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**height** | Option<**i32**> | Optional block height to schedule the refresh at. When set, the refresh fee is priced at that height and the server includes the participation in the first round once the chain tip reaches it; when omitted, the participation is eligible for the next round. | [optional]
**vtxos** | **Vec<String>** | List of VTXO IDs to refresh. The sum of the VTXOs being refreshed must be >= [P2TR_DUST](bitcoin_ext::P2TR_DUST). Keep in mind that fees set out in [RefreshFees](crate::cli::fees::RefreshFees) will be deducted from the newly created VTXO, this value must also be >= [P2TR_DUST](bitcoin_ext::P2TR_DUST). | 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


