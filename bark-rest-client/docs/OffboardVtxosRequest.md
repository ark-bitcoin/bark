# OffboardVtxosRequest

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**address** | Option<**String**> | Optional Bitcoin address to send to. If not provided, uses the onchain wallet's address | [optional]
**vtxos** | **Vec<String>** | List of VTXO IDs to offboard. The sum of the VTXOs being refreshed must be >= [P2TR_DUST](bitcoin_ext::P2TR_DUST) after the server-configured [OffboardFees](crate::cli::OffboardFees) are deducted. | 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


