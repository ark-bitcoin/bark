# \LightningApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**generate_invoice**](LightningApi.md#generate_invoice) | **POST** /api/v1/lightning/receives/invoice | Create a BOLT11 invoice
[**get_receive_status**](LightningApi.md#get_receive_status) | **GET** /api/v1/lightning/receives/{identifier} | Get receive status
[**list_receive_statuses**](LightningApi.md#list_receive_statuses) | **GET** /api/v1/lightning/receives | List all pending receive statuses
[**pay**](LightningApi.md#pay) | **POST** /api/v1/lightning/pay | Send a Lightning payment



## generate_invoice

> models::InvoiceInfo generate_invoice(lightning_invoice_request)
Create a BOLT11 invoice

Generates a new BOLT11 invoice for the specified amount via the Ark server, creating a pending Lightning receive.

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
Get receive status

Returns the status of a specified Lightning receive, identified by its payment hash, invoice string, or preimage. The response tracks progress through timestamps: `htlc_vtxos` is populated once HTLCs are created by the Ark server, `preimage_revealed_at` records when the preimage was sent, and `finished_at` indicates the receive has settled or been canceled.

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
List all pending receive statuses

Returns the statuses of all pending Lightning receives, ordered from oldest to newest. A receive is pending until its `finished_at` timestamp is set, indicating it has settled or been canceled.

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
Send a Lightning payment

Sends a payment to a Lightning destination. Accepts a BOLT11 invoice, BOLT12 offer, or Lightning address. The `amount_sat` field is required for Lightning addresses but optional for invoices and offers. Comments are only supported for Lightning addresses.

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

