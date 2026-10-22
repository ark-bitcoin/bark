# SendRequest

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**amount_sat** | Option<**i64**> | The amount to send (in satoshis). Optional when the destination carries an amount, such as a BOLT11 invoice or a BIP 321 URI with an amount. Depending on the `destination`, the wallet must contain this amount plus any fees configured by the server in [FeeSchedule](crate::cli::fees::FeeSchedule). | [optional]
**comment** | Option<**String**> | An optional comment, only supported when paying to lightning addresses | [optional]
**destination** | **String** | The destination can be an Ark address, a BOLT11 invoice, a BOLT12 offer, a lightning address, LNURL, a bitcoin address or a BIP 321 URI | 
**method** | Option<[**models::PaymentMethodKind**](PaymentMethodKind.md)> | For a destination with several payment methods, such as a BIP 321 URI, the kind of method to pay with. When empty, the wallet picks Ark, then Lightning, then on-chain. | [optional]
**retry_for_secs** | Option<**i64**> | For lightning destinations, how many seconds the Ark server should keep trying to pay, capped to the server's maximum. The server picks its default when empty. | [optional]

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


