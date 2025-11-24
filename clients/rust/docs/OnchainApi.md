# \OnchainApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**onchain_address**](OnchainApi.md#onchain_address) | **POST** /api/v1/onchain/addresses/next | 
[**onchain_balance**](OnchainApi.md#onchain_balance) | **GET** /api/v1/onchain/balance | 
[**onchain_drain**](OnchainApi.md#onchain_drain) | **POST** /api/v1/onchain/drain | 
[**onchain_send**](OnchainApi.md#onchain_send) | **POST** /api/v1/onchain/send | 
[**onchain_send_many**](OnchainApi.md#onchain_send_many) | **POST** /api/v1/onchain/send-many | 
[**onchain_sync**](OnchainApi.md#onchain_sync) | **POST** /api/v1/onchain/sync | 
[**onchain_transactions**](OnchainApi.md#onchain_transactions) | **GET** /api/v1/onchain/transactions | 
[**onchain_utxos**](OnchainApi.md#onchain_utxos) | **GET** /api/v1/onchain/utxos | 



## onchain_address

> models::Address onchain_address()


Generates a new onchain address and stores its index in the onchain wallet database

### Parameters

This endpoint does not need any parameter.

### Return type

[**models::Address**](Address.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## onchain_balance

> models::OnchainBalance onchain_balance()


Returns the current onchain wallet balance

### Parameters

This endpoint does not need any parameter.

### Return type

[**models::OnchainBalance**](OnchainBalance.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## onchain_drain

> models::Send onchain_drain(onchain_drain_request)


Sends all onchain wallet funds to the given address

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**onchain_drain_request** | [**OnchainDrainRequest**](OnchainDrainRequest.md) |  | [required] |

### Return type

[**models::Send**](Send.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## onchain_send

> models::Send onchain_send(onchain_send_request)


Sends a payment to the given onchain address

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**onchain_send_request** | [**OnchainSendRequest**](OnchainSendRequest.md) |  | [required] |

### Return type

[**models::Send**](Send.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## onchain_send_many

> models::Send onchain_send_many(onchain_send_many_request)


Sends multiple payments to provided onchain addresses

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**onchain_send_many_request** | [**OnchainSendManyRequest**](OnchainSendManyRequest.md) |  | [required] |

### Return type

[**models::Send**](Send.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## onchain_sync

> onchain_sync()


Syncs the onchain wallet

### Parameters

This endpoint does not need any parameter.

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## onchain_transactions

> Vec<models::TransactionInfo> onchain_transactions()


Returns all the onchain wallet transactions

### Parameters

This endpoint does not need any parameter.

### Return type

[**Vec<models::TransactionInfo>**](TransactionInfo.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## onchain_utxos

> Vec<models::UtxoInfo> onchain_utxos()


Returns all the onchain wallet UTXOs

### Parameters

This endpoint does not need any parameter.

### Return type

[**Vec<models::UtxoInfo>**](UtxoInfo.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

