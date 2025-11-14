# \LightningApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**lightning_invoice**](LightningApi.md#lightning_invoice) | **POST** /api/v1/lightning/receive/invoice | 
[**lightning_invoices**](LightningApi.md#lightning_invoices) | **GET** /api/v1/lightning/receive/invoices | 
[**lightning_pay**](LightningApi.md#lightning_pay) | **POST** /api/v1/lightning/pay | 
[**lightning_status**](LightningApi.md#lightning_status) | **GET** /api/v1/lightning/receive/status | 



## lightning_invoice

> models::InvoiceInfo lightning_invoice(lightning_invoice_request)


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


## lightning_invoices

> Vec<models::LightningReceiveInfo> lightning_invoices()


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


## lightning_pay

> models::LightningPayResponse lightning_pay(lightning_pay_request)


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


## lightning_status

> models::LightningStatusResponse lightning_status(filter, preimage)


### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**filter** | Option<**String**> | Payment hash or invoice string |  |
**preimage** | Option<**String**> | Filter by preimage |  |

### Return type

[**models::LightningStatusResponse**](LightningStatusResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

