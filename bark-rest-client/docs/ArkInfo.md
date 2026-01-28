# ArkInfo

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**fees** | [**models::FeeSchedule**](FeeSchedule.md) | The fee schedule outlining any fees that must be paid to interact with the Ark server. | 
**htlc_expiry_delta** | **i32** |  | 
**htlc_send_expiry_delta** | **i32** |  | 
**ln_receive_anti_dos_required** | **bool** | Indicates whether the Ark server requires clients to either provide a VTXO ownership proof, or a lightning receive token when preparing a lightning claim. | 
**mailbox_pubkey** | **String** | The pubkey used for blinding unified mailbox IDs | 
**max_user_invoice_cltv_delta** | **i32** | Maximum CLTV delta server will allow clients to request an invoice generation with. | 
**max_vtxo_amount** | **i64** | Maximum amount of a VTXO | 
**min_board_amount_sat** | **i64** | Minimum amount for a board the server will cosign | 
**nb_round_nonces** | **i32** | Number of nonces per round | 
**network** | **String** | The bitcoin network the server operates on | 
**offboard_feerate_sat_per_kvb** | **i64** | offboard feerate in sat per kvb | 
**offboard_fixed_fee_vb** | **i64** | fixed number of vb charged additinally for an offboard this is charged after being multiplied with the offboard feerate | 
**required_board_confirmations** | **i32** | The number of confirmations required to register a board vtxo | 
**round_interval** | **String** | The interval between each round | 
**server_pubkey** | **String** | The Ark server pubkey | 
**vtxo_exit_delta** | **i32** |  | 
**vtxo_expiry_delta** | **i32** |  | 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


