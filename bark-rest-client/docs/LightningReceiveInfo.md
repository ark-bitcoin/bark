# LightningReceiveInfo

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**amount_sat** | **i64** | The amount of the lightning receive, if known. | 
**finished_at** | Option<**String**> | The timestamp at which the lightning receive was finished. | [optional]
**htlc_vtxo_ids** | **Vec<String>** | IDs of the HTLC-recv VTXOs granted by the server, if any.  Empty until the inbound HTLC has been received and prepared. | 
**htlc_vtxos** | [**Vec<models::WalletVtxoInfo>**](WalletVtxoInfo.md) | The HTLC VTXOs granted by the server for the lightning receive. | 
**invoice** | **String** | The invoice string, if known. | 
**payment_hash** | **String** | The payment hash linked to the lightning receive | 
**payment_preimage** | Option<**String**> | The payment preimage, if known. | [optional]
**preimage_revealed_at** | Option<**String**> | The timestamp at which the preimage was revealed. | [optional]
**settled_at** | Option<**String**> | The timestamp at which the receive settled, if it has. | [optional]
**state** | **String** | Lifecycle phase of the receive: `awaiting-payment`, `htlcs-ready`, `preimage-revealed`, or `settled`. | 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


