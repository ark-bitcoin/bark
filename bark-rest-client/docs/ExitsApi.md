# \ExitsApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**exit_claim_all**](ExitsApi.md#exit_claim_all) | **POST** /api/v1/exits/claim/all | Claim all exited VTXOs
[**exit_claim_vtxos**](ExitsApi.md#exit_claim_vtxos) | **POST** /api/v1/exits/claim/vtxos | Claim specific exited VTXOs
[**exit_progress**](ExitsApi.md#exit_progress) | **POST** /api/v1/exits/progress | Progress exits
[**exit_start_all**](ExitsApi.md#exit_start_all) | **POST** /api/v1/exits/start/all | Start exit for all VTXOs
[**exit_start_vtxos**](ExitsApi.md#exit_start_vtxos) | **POST** /api/v1/exits/start/vtxos | Start exit for specific VTXOs
[**get_all_exit_status**](ExitsApi.md#get_all_exit_status) | **GET** /api/v1/exits/status | List all exit statuses
[**get_exit_status_by_vtxo_id**](ExitsApi.md#get_exit_status_by_vtxo_id) | **GET** /api/v1/exits/status/{vtxo_id} | Get exit status



## exit_claim_all

> models::ExitClaimResponse exit_claim_all(exit_claim_all_request)
Claim all exited VTXOs

Sweeps all claimable exit outputs into a single on-chain transaction sent to the specified address. Unlike `progress`, the daemon does not claim automatically—this endpoint must be called manually. Poll the `status` endpoint or call `progress` and check for `done: true` to know when VTXOs are ready to claim. This is the final step of the emergency exit process—the bitcoin is not considered back on-chain until this transaction confirms.

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
Claim specific exited VTXOs

Sweeps the specified claimable exit outputs into a single on-chain transaction sent to the specified address. Unlike `progress`, the daemon does not claim automatically—this endpoint must be called manually. Poll the `status` endpoint or call `progress` and check for `done: true` to know when VTXOs are ready to claim. This is the final step of the emergency exit process—the bitcoin is not considered back on-chain until this transaction confirms.

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
Progress exits

Triggers all in-progress exits to advance by one step. The daemon already progresses exits automatically in the background—use this endpoint when you want immediate progress rather than waiting for the next automatic cycle. On each call, the endpoint checks whether previously broadcast transactions have confirmed and, if so, creates and broadcasts the next transaction in the sequence. The on-chain wallet must have sufficient bitcoin to cover transaction fees.

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
Start exit for all VTXOs

Registers all wallet VTXOs for emergency exit. The daemon automatically progresses registered exits in the background at the cadence defined by `SLOW_INTERVAL`, creating and broadcasting the required transactions in sequence. Once all exit transactions are confirmed and the timelock has elapsed, call `claim` to sweep the resulting outputs to an on-chain address.

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
Start exit for specific VTXOs

Registers the specified VTXOs for emergency exit. The daemon automatically progresses registered exits in the background at the cadence defined by `SLOW_INTERVAL`, creating and broadcasting the required transactions in sequence. Once all exit transactions are confirmed and the timelock has elapsed, call `claim` to sweep the resulting outputs to an on-chain address.

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
List all exit statuses

Returns the current state of every emergency exit in the wallet. Each entry includes which phase the exit is in (start, processing, awaiting-delta, claimable, claim-in-progress, or claimed), and optionally the full state transition history and the exit transaction packages with their CPFP children.

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
Get exit status

Returns the current state of an emergency exit for the specified VTXO, including which phase the exit is in (start, processing, awaiting-delta, claimable, claim-in-progress, or claimed). Optionally includes the full state transition history and the exit transaction packages with their CPFP children.

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

