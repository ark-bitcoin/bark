# \LightningApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**generate_invoice**](LightningApi.md#generate_invoice) | **POST** /api/v1/lightning/receives/invoice | 
[**get_receive_status**](LightningApi.md#get_receive_status) | **GET** /api/v1/lightning/receives/{identifier} | 
[**list_receive_statuses**](LightningApi.md#list_receive_statuses) | **GET** /api/v1/lightning/receives | 
[**pay**](LightningApi.md#pay) | **POST** /api/v1/lightning/pay | 



## generate_invoice

> models::InvoiceInfo generate_invoice(lightning_invoice_request)


Generates a new lightning invoice with the given amount

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**lightning_invoice_request** | [**LightningInvoiceRequest**](LightningInvoiceRequest.md) |  | [required] |

### Return type

[**models::InvoiceInfo**](InvoiceInfo.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## get_receive_status

> models::LightningReceiveInfo get_receive_status(identifier)


Returns the status of a lightning receive for the provided filter

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**identifier** | **String** | Payment hash, invoice string or preimage to search for | [required] |

### Return type

[**models::LightningReceiveInfo**](LightningReceiveInfo.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## list_receive_statuses

> Vec<models::LightningReceiveInfo> list_receive_statuses()


Returns all the current pending receive statuses

### Parameters

This endpoint does not need any parameter.

### Return type

[**Vec<models::LightningReceiveInfo>**](LightningReceiveInfo.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## pay

> models::LightningPayResponse pay(lightning_pay_request)


Sends a payment to the given lightning destination

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**lightning_pay_request** | [**LightningPayRequest**](LightningPayRequest.md) |  | [required] |

### Return type

[**models::LightningPayResponse**](LightningPayResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

