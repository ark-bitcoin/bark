# \BoardsApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**board_all**](BoardsApi.md#board_all) | **POST** /api/v1/boards/board-all | 
[**board_amount**](BoardsApi.md#board_amount) | **POST** /api/v1/boards/board-amount | 
[**get_pending_boards**](BoardsApi.md#get_pending_boards) | **GET** /api/v1/boards/ | 



## board_all

> models::PendingBoardInfo board_all()


Board all the onchain funds to the offchain wallet

### Parameters

This endpoint does not need any parameter.

### Return type

[**models::PendingBoardInfo**](PendingBoardInfo.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## board_amount

> models::PendingBoardInfo board_amount(board_request)


Board the given amount of onchain funds to the offchain wallet

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**board_request** | [**BoardRequest**](BoardRequest.md) |  | [required] |

### Return type

[**models::PendingBoardInfo**](PendingBoardInfo.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## get_pending_boards

> Vec<models::PendingBoardInfo> get_pending_boards()


### Parameters

This endpoint does not need any parameter.

### Return type

[**Vec<models::PendingBoardInfo>**](PendingBoardInfo.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

