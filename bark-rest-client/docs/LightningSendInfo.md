# LightningSendInfo

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**invoice** | Option<**String**> | The invoice string, if known. | [optional]
**payment_hash** | **String** | The payment hash of the outgoing lightning payment | 
**preimage** | Option<**String**> | The payment preimage, revealed once the payment succeeded. | [optional]
**state** | **String** | Lifecycle phase of the send: `unknown`, `start`, `htlc-received`, `payment-initiated`, `revocable-htlcs`, `revocation-stuck`, or `paid`. | 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


