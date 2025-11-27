# \BoardsApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**board_all**](BoardsApi.md#board_all) | **POST** /api/v1/boards/board-all | 
[**board_amount**](BoardsApi.md#board_amount) | **POST** /api/v1/boards/board-amount | 



## board_all

> models::Board board_all()


Board all the onchain funds to the offchain wallet

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


## board_amount

> models::Board board_amount(board_request)


Board the given amount of onchain funds to the offchain wallet

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

