# LightningPayRequest

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**amount_sat** | Option<**i64**> | The amount to send (in satoshis). Optional for bolt11 invoices with amount. This must be higher than the minimum fee laid out in server-configured [LightningSendFees](crate::cli::fees::LightningSendFees). The wallet must also contain enough funds to cover the amount plus any fees. | [optional]
**comment** | Option<**String**> | An optional comment, only supported when paying to lightning addresses | [optional]
**destination** | **String** | The invoice, offer, or lightning address to pay | 
**retry_for_secs** | Option<**i64**> | How many seconds the Ark server should keep trying to pay, capped to the server's maximum. The server picks its default when empty. | [optional]

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


