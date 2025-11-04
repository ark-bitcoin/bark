# LightningReceiveInfo

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**htlc_vtxos** | Option<[**Vec<models::WalletVtxoInfo>**](WalletVtxoInfo.md)> | The HTLC VTXOs granted by the server for the lightning receive  Only present if the lightning HTLC has been received by the server. | 
**invoice** | **String** | The invoice string | 
**payment_hash** | **String** | The payment hash linked to the lightning receive info | 
**payment_preimage** | **String** | The payment preimage linked to the lightning receive info | 
**preimage_revealed_at** | Option<**String**> | The timestamp at which the preimage was revealed | [optional]

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


