# \HistoryApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**list**](HistoryApi.md#list) | **GET** /api/v1/history/ | Get wallet history
[**update_metadata**](HistoryApi.md#update_metadata) | **POST** /api/v1/history/{id}/metadata | Patch movement metadata



## list

> Vec<models::Movement> list()
Get wallet history

Returns the full history of wallet movements ordered from newest to oldest. A movement represents any wallet operation that affects VTXOs—an arkoor send or receive, Lightning send or receive, board, offboard, or refresh. Each entry records which VTXOs were consumed and produced, the effective balance change (if any), fees paid, and the operation status.

### Parameters

This endpoint does not need any parameter.

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

