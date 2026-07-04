# Bip321UriRequest

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**amount_sat** | Option<**i64**> | Optional amount (in satoshis) to request. When set, it is embedded in the URI and used to create the BOLT11 invoice. Any server-configured [LightningReceiveFees](crate::cli::fees::LightningReceiveFees) are deducted from the amount the client ultimately receives over Lightning. | [optional]
**label** | Option<**String**> | Optional label describing the payment, recorded in the URI's `label`. | [optional]
**message** | Option<**String**> | Optional message describing the payment, recorded in the URI's `message`. | [optional]
**onchain** | Option<**bool**> | Whether to include a fresh on-chain address as a payment destination. Defaults to `false`. | [optional]

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


