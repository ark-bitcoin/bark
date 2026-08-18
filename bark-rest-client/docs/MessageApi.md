# \MessageApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**sign_message**](MessageApi.md#sign_message) | **POST** /api/v1/message/sign | Sign a message
[**verify_message**](MessageApi.md#verify_message) | **POST** /api/v1/message/verify | Verify a signed message



## sign_message

> models::SignedMessage sign_message(sign_message_request)
Sign a message

Signs an arbitrary message with a BIP-340 Schnorr signature over a prefixed hash (`SHA256(\"bark/message\" || message)`) of the UTF-8 message bytes. The message is signed with the key of the given Ark address, which must be one of the wallet's own addresses; addresses that do not belong to the wallet are rejected. The resulting signature can be checked with the `/message/verify` endpoint.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**sign_message_request** | [**SignMessageRequest**](SignMessageRequest.md) |  | [required] |

### Return type

[**models::SignedMessage**](SignedMessage.md)

### Authorization

[bearer](../README.md#bearer)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## verify_message

> models::MessageVerification verify_message(verify_message_request)
Verify a signed message

Verifies a BIP-340 Schnorr signature over a prefixed hash (`SHA256(\"bark/message\" || message)`) of the UTF-8 message bytes, as created by the `/message/sign` endpoint. The signature is checked against a public key (`pubkey`) or against the user public key of an Ark address (`address`); exactly one of the two must be set. Verification is stateless and works for signatures made by any wallet, not just this one.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**verify_message_request** | [**VerifyMessageRequest**](VerifyMessageRequest.md) |  | [required] |

### Return type

[**models::MessageVerification**](MessageVerification.md)

### Authorization

[bearer](../README.md#bearer)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

