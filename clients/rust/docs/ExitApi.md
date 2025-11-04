# \ExitApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**exit_claim**](ExitApi.md#exit_claim) | **POST** /api/v1/exit/claim | 
[**exit_list**](ExitApi.md#exit_list) | **GET** /api/v1/exit/list | 
[**exit_progress**](ExitApi.md#exit_progress) | **POST** /api/v1/exit/progress | 
[**exit_start_all**](ExitApi.md#exit_start_all) | **POST** /api/v1/exit/start/all | 
[**exit_start_vtxos**](ExitApi.md#exit_start_vtxos) | **POST** /api/v1/exit/start/vtxos | 
[**exit_status**](ExitApi.md#exit_status) | **GET** /api/v1/exit/status | 



## exit_claim

> models::ExitClaimResponse exit_claim(exit_claim_request)


### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**exit_claim_request** | [**ExitClaimRequest**](ExitClaimRequest.md) |  | [required] |

### Return type

[**models::ExitClaimResponse**](ExitClaimResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## exit_list

> Vec<models::ExitTransactionStatus> exit_list(history, transactions)


### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**history** | Option<**bool**> | Whether to include the detailed history of the exit process |  |
**transactions** | Option<**bool**> | Whether to include the exit transactions and their CPFP children |  |

### Return type

[**Vec<models::ExitTransactionStatus>**](ExitTransactionStatus.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## exit_progress

> models::ExitProgressResponse exit_progress(exit_progress_request)


### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**exit_progress_request** | [**ExitProgressRequest**](ExitProgressRequest.md) |  | [required] |

### Return type

[**models::ExitProgressResponse**](ExitProgressResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## exit_start_all

> models::ExitStartResponse exit_start_all()


### Parameters

This endpoint does not need any parameter.

### Return type

[**models::ExitStartResponse**](ExitStartResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## exit_start_vtxos

> models::ExitStartResponse exit_start_vtxos(exit_start_request)


### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**exit_start_request** | [**ExitStartRequest**](ExitStartRequest.md) |  | [required] |

### Return type

[**models::ExitStartResponse**](ExitStartResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## exit_status

> models::ExitTransactionStatus exit_status(vtxo, history, transactions)


### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**vtxo** | **String** | The VTXO to check the exit status of | [required] |
**history** | Option<**bool**> | Whether to include the detailed history of the exit process |  |
**transactions** | Option<**bool**> | Whether to include the exit transactions and their CPFP children |  |

### Return type

[**models::ExitTransactionStatus**](ExitTransactionStatus.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

