# LightningInvoiceRequest

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**amount_sat** | **i64** | The amount to create invoice for (in satoshis). This is the amount the payee will pay but the final amount received by the client will have any server-configured [LightningReceiveFees](crate::cli::fees::LightningReceiveFees) deducted. | 
**description** | Option<**String**> | Optional description embedded in the invoice as its memo. | [optional]
**token** | Option<**String**> | Optional lightning receive token for authentication of the claim, if the server requires one and there are no existing spendable VTXOs to prove ownership of. | [optional]

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


