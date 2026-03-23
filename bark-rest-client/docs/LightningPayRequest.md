# LightningPayRequest

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**amount_sat** | Option<**i64**> | The amount to send (in satoshis). Optional for bolt11 invoices with amount. This must be higher than the minimum fee laid out in server-configured [LightningSendFees](crate::cli::LightningSendFees). The wallet must also contain enough funds to cover the amount plus any fees. | [optional]
**comment** | Option<**String**> | An optional comment, only supported when paying to lightning addresses | [optional]
**destination** | **String** | The invoice, offer, or lightning address to pay | 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


