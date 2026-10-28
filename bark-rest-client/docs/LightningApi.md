# \LightningApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**cancel_receive**](LightningApi.md#cancel_receive) | **DELETE** /api/v1/lightning/receives/{identifier} | Cancel a pending receive
[**generate_invoice**](LightningApi.md#generate_invoice) | **POST** /api/v1/lightning/receives/invoice | Create a BOLT11 invoice
[**generate_invoice_for_address**](LightningApi.md#generate_invoice_for_address) | **POST** /api/v1/lightning/receives/invoice/for-address | Create a BOLT11 invoice for an Ark address
[**get_receive_status**](LightningApi.md#get_receive_status) | **GET** /api/v1/lightning/receives/{identifier} | Get receive status
[**get_send_status**](LightningApi.md#get_send_status) | **GET** /api/v1/lightning/sends/{identifier} | Get send status
[**list_receive_statuses**](LightningApi.md#list_receive_statuses) | **GET** /api/v1/lightning/receives | List all pending receive statuses
[**pay**](LightningApi.md#pay) | **POST** /api/v1/lightning/pay | Send a Lightning payment



## cancel_receive

> cancel_receive(identifier)
Cancel a pending receive

Cancels a pending Lightning receive identified by its payment hash or invoice string. The server will refuse cancellation if HTLC-recv VTXOs have already been granted. Bark also prevents cancellation when the preimage has been revealed.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**identifier** | **String** | Payment hash or invoice string | [required] |

### Return type

 (empty response body)

### Authorization

[bearer](../README.md#bearer)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## generate_invoice

> models::InvoiceInfo generate_invoice(lightning_invoice_request)
Create a BOLT11 invoice

Generates a new BOLT11 invoice for the specified amount via the Ark server, creating a pending Lightning receive. The invoice expires after `expiry_secs` if given, otherwise after the Ark server's invoice expiry, which is also the longest it accepts.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**lightning_invoice_request** | [**LightningInvoiceRequest**](LightningInvoiceRequest.md) |  | [required] |

### Return type

[**models::InvoiceInfo**](InvoiceInfo.md)

### Authorization

[bearer](../README.md#bearer)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## generate_invoice_for_address

> models::InvoiceInfo generate_invoice_for_address(lightning_invoice_for_address_request)
Create a BOLT11 invoice for an Ark address

Generates a new BOLT11 invoice. When paid, the wallet claims the Lightning receive and forwards the resulting Ark VTXO to the supplied Ark address mailbox. The invoice expires after `expiry_secs` if given, otherwise after the Ark server's invoice expiry, which is also the longest it accepts.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**lightning_invoice_for_address_request** | [**LightningInvoiceForAddressRequest**](LightningInvoiceForAddressRequest.md) |  | [required] |

### Return type

[**models::InvoiceInfo**](InvoiceInfo.md)

### Authorization

[bearer](../README.md#bearer)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## get_receive_status

> models::LightningReceiveInfo get_receive_status(identifier)
Get receive status

Returns the status of a specified Lightning receive, identified by its payment hash, invoice string, or preimage. `state` tracks its progress and `settled_at` records when it settled. A receive that ended without settling, for example a canceled one, is no longer known and returns 404.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**identifier** | **String** | Payment hash, invoice string or preimage to search for | [required] |

### Return type

[**models::LightningReceiveInfo**](LightningReceiveInfo.md)

### Authorization

[bearer](../README.md#bearer)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## get_send_status

> models::LightningSendInfo get_send_status(identifier)
Get send status

Returns the status of a specified outgoing Lightning payment, identified by its payment hash or invoice string. The `state` field tracks the payment lifecycle from `start` through `paid`; the preimage is included once the payment succeeded. If the wallet does not recognize the payment hash, it will return `unknown`. This is a read on the status in the db, so it does not trigger any `sync` before checking the state.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**identifier** | **String** | Payment hash or invoice string to search for | [required] |

### Return type

[**models::LightningSendInfo**](LightningSendInfo.md)

### Authorization

[bearer](../README.md#bearer)

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

[bearer](../README.md#bearer)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## pay

> models::LightningPayResponse pay(lightning_pay_request)
Send a Lightning payment

Sends a payment to a Lightning destination. Accepts a BOLT11 invoice, BOLT12 offer, Lightning address, or LNURL. The `amount_sat` field is required for Lightning addresses and LNURL but optional for invoices and offers that already encode an amount. Comments are only supported for Lightning addresses and LNURL.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**lightning_pay_request** | [**LightningPayRequest**](LightningPayRequest.md) |  | [required] |

### Return type

[**models::LightningPayResponse**](LightningPayResponse.md)

### Authorization

[bearer](../README.md#bearer)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

