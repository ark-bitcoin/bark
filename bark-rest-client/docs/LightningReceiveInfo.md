# LightningReceiveInfo

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**amount_sat** | **i64** | The amount of the lightning receive | 
**finished_at** | Option<**String**> | The timestamp at which the lightning receive was finished | [optional]
**htlc_vtxos** | [**Vec<models::WalletVtxoInfo>**](WalletVtxoInfo.md) | The HTLC VTXOs granted by the server for the lightning receive  Empty if the lightning HTLC has not yet been received by the server. | 
**invoice** | **String** | The invoice string | 
**payment_hash** | **String** | The payment hash linked to the lightning receive info | 
**payment_preimage** | **String** | The payment preimage linked to the lightning receive info | 
**preimage_revealed_at** | Option<**String**> | The timestamp at which the preimage was revealed | [optional]

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


