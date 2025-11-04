# \BoardApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**board**](BoardApi.md#board) | **POST** /api/v1/board/board | 
[**board_all**](BoardApi.md#board_all) | **POST** /api/v1/board/board/all | 



## board

> models::Board board(board_request)


### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**board_request** | [**BoardRequest**](BoardRequest.md) |  | [required] |

### Return type

[**models::Board**](Board.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## board_all

> models::Board board_all()


### Parameters

This endpoint does not need any parameter.

### Return type

[**models::Board**](Board.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

