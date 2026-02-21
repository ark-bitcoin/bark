# \BitcoinApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**tip**](BitcoinApi.md#tip) | **GET** /api/v1/bitcoin/tip | Get bitcoin tip height



## tip

> models::TipResponse tip()
Get bitcoin tip height

Queries the wallet's chain source for the block height of the latest block on the best chain.

### Parameters

This endpoint does not need any parameter.

### Return type

[**models::TipResponse**](TipResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

