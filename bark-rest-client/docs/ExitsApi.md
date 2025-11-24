# \ExitsApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**exit_claim_all**](ExitsApi.md#exit_claim_all) | **POST** /api/v1/exits/claim/all | 
[**exit_claim_vtxos**](ExitsApi.md#exit_claim_vtxos) | **POST** /api/v1/exits/claim/vtxos | 
[**exit_progress**](ExitsApi.md#exit_progress) | **POST** /api/v1/exits/progress | 
[**exit_start_all**](ExitsApi.md#exit_start_all) | **POST** /api/v1/exits/start/all | 
[**exit_start_vtxos**](ExitsApi.md#exit_start_vtxos) | **POST** /api/v1/exits/start/vtxos | 
[**get_all_exit_status**](ExitsApi.md#get_all_exit_status) | **GET** /api/v1/exits/status | 
[**get_exit_status_by_vtxo_id**](ExitsApi.md#get_exit_status_by_vtxo_id) | **GET** /api/v1/exits/status/{vtxo_id} | 



## exit_claim_all

> models::ExitClaimResponse exit_claim_all(exit_claim_all_request)


Claims all claimable exited VTXOs to the given destination address

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**exit_claim_all_request** | [**ExitClaimAllRequest**](ExitClaimAllRequest.md) |  | [required] |

### Return type

[**models::ExitClaimResponse**](ExitClaimResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## exit_claim_vtxos

> models::ExitClaimResponse exit_claim_vtxos(exit_claim_vtxos_request)


Claims the given exited VTXOs to the given destination address

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**exit_claim_vtxos_request** | [**ExitClaimVtxosRequest**](ExitClaimVtxosRequest.md) |  | [required] |

### Return type

[**models::ExitClaimResponse**](ExitClaimResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## exit_progress

> models::ExitProgressResponse exit_progress(exit_progress_request)


Progresses the exit process of all current exits until it completes

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


Starts an exit for all VTXOs

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


Starts an exit for the given VTXOs

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


## get_all_exit_status

> Vec<models::ExitTransactionStatus> get_all_exit_status(history, transactions)


Returns all the current in-progress, completed and failed exits

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


## get_exit_status_by_vtxo_id

> models::ExitTransactionStatus get_exit_status_by_vtxo_id(vtxo_id, history, transactions)


Returns the status of the exit for the given VTXO

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**vtxo_id** | **String** | The VTXO to check the exit status of | [required] |
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

