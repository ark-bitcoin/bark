# VerifyMessageRequest

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**address** | Option<**String**> | The Ark address whose user public key to verify the signature against | [optional]
**message** | **String** | The message that was signed | 
**pubkey** | Option<**String**> | The public key to verify the signature against | [optional]
**signature** | **String** | The BIP-340 Schnorr signature over the message digest `SHA256(\"bark/message\" || message)`, in hex | 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


