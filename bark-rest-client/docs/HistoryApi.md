# \HistoryApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**list**](HistoryApi.md#list) | **GET** /api/v1/history | Get wallet history
[**update_metadata**](HistoryApi.md#update_metadata) | **POST** /api/v1/history/{id}/metadata | Patch movement metadata



## list

> Vec<models::Movement> list(r#type, value)
Get wallet history

Returns the history of wallet movements ordered from newest to oldest. A movement represents any wallet operation that affects VTXOs—an arkoor send or receive, Lightning send or receive, board, offboard, or refresh. Each entry records which VTXOs were consumed and produced, the effective balance change (if any), fees paid, and the operation status. Supplying the `type` and `value` query parameters (together) restricts the result to movements involving that single payment method, such as all payments sent to one address.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**r#type** | Option<**String**> | Payment method type tag to filter by, e.g. `ark`, `bitcoin`, `output-script`, `invoice`, `offer`, `lightning-address`, `lnurl` or `custom`. Must be supplied together with `value`. |  |
**value** | Option<**String**> | Payment method value to filter by, e.g. the destination address or invoice. Must be supplied together with `type`. |  |

### Return type

[**Vec<models::Movement>**](Movement.md)

### Authorization

[bearer](../README.md#bearer)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## update_metadata

> update_metadata(id, body)
Patch movement metadata

Applies an [RFC 7396](https://www.rfc-editor.org/rfc/rfc7396) JSON Merge Patch to a movement's metadata. Use this to annotate history entries after the fact (e.g. refund notes, counterparty info). Keys set to `null` are removed; other values are recursively merged.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **i32** | Movement identifier. | [required] |
**body** | Option<**serde_json::Value**> | RFC 7396 JSON Merge Patch. The body is applied directly to the movement's metadata object: any field with value `null` is removed, every other field is recursively merged. | [required] |

### Return type

 (empty response body)

### Authorization

[bearer](../README.md#bearer)

### HTTP request headers

- **Content-Type**: application/merge-patch+json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

