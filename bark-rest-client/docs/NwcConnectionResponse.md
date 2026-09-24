# NwcConnectionResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**client_pubkey** | **String** | The connection's client public key, used to revoke it later. | 
**uri** | **String** | The `nostr+walletconnect://` URI to give the app.  This is the only time the client secret is returned. It is not stored, so a connection that is lost has to be revoked and recreated. | 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


