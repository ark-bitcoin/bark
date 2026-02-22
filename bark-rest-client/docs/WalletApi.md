# \WalletApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**address**](WalletApi.md#address) | **POST** /api/v1/wallet/addresses/next | 
[**ark_info**](WalletApi.md#ark_info) | **GET** /api/v1/wallet/ark-info | 
[**balance**](WalletApi.md#balance) | **GET** /api/v1/wallet/balance | 
[**connected**](WalletApi.md#connected) | **GET** /api/v1/wallet/connected | 
[**create_wallet**](WalletApi.md#create_wallet) | **POST** /api/v1/wallet/create | 
[**history**](WalletApi.md#history) | **GET** /api/v1/wallet/history | 
[**import_vtxo**](WalletApi.md#import_vtxo) | **POST** /api/v1/wallet/import-vtxo | 
[**movements**](WalletApi.md#movements) | **GET** /api/v1/wallet/movements | 
[**next_round**](WalletApi.md#next_round) | **GET** /api/v1/wallet/next-round | 
[**offboard_all**](WalletApi.md#offboard_all) | **POST** /api/v1/wallet/offboard/all | 
[**offboard_vtxos**](WalletApi.md#offboard_vtxos) | **POST** /api/v1/wallet/offboard/vtxos | 
[**peak_address**](WalletApi.md#peak_address) | **GET** /api/v1/wallet/addresses/index/{index} | 
[**pending_rounds**](WalletApi.md#pending_rounds) | **GET** /api/v1/wallet/rounds | 
[**refresh_all**](WalletApi.md#refresh_all) | **POST** /api/v1/wallet/refresh/all | 
[**refresh_counterparty**](WalletApi.md#refresh_counterparty) | **POST** /api/v1/wallet/refresh/counterparty | 
[**refresh_vtxos**](WalletApi.md#refresh_vtxos) | **POST** /api/v1/wallet/refresh/vtxos | 
[**send**](WalletApi.md#send) | **POST** /api/v1/wallet/send | 
[**send_onchain**](WalletApi.md#send_onchain) | **POST** /api/v1/wallet/send-onchain | 
[**sync**](WalletApi.md#sync) | **POST** /api/v1/wallet/sync | 
[**vtxos**](WalletApi.md#vtxos) | **GET** /api/v1/wallet/vtxos | 



## address

> models::ArkAddressResponse address()


Generates a new Ark address and stores it in the wallet database

### Parameters

This endpoint does not need any parameter.

### Return type

[**models::ArkAddressResponse**](ArkAddressResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## ark_info

> models::ArkInfo ark_info()


Returns the current Ark infos

### Parameters

This endpoint does not need any parameter.

### Return type

[**models::ArkInfo**](ArkInfo.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## balance

> models::Balance balance()


Returns the current wallet balance

### Parameters

This endpoint does not need any parameter.

### Return type

[**models::Balance**](Balance.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## connected

> models::ConnectedResponse connected()


Returns whether the wallet is currently connected to the Ark server

### Parameters

This endpoint does not need any parameter.

### Return type

[**models::ConnectedResponse**](ConnectedResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## create_wallet

> models::CreateWalletResponse create_wallet(create_wallet_request)


Creates a new wallet

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**create_wallet_request** | [**CreateWalletRequest**](CreateWalletRequest.md) |  | [required] |

### Return type

[**models::CreateWalletResponse**](CreateWalletResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## history

> Vec<models::Movement> history()


Returns all the wallet history

### Parameters

This endpoint does not need any parameter.

### Return type

[**Vec<models::Movement>**](Movement.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## import_vtxo

> Vec<models::WalletVtxoInfo> import_vtxo(import_vtxo_request)


Imports a raw serialized VTXO into the wallet

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**import_vtxo_request** | [**ImportVtxoRequest**](ImportVtxoRequest.md) |  | [required] |

### Return type

[**Vec<models::WalletVtxoInfo>**](WalletVtxoInfo.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## movements

> Vec<models::Movement> movements()


Deprecated: Use history instead

### Parameters

This endpoint does not need any parameter.

### Return type

[**Vec<models::Movement>**](Movement.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## next_round

> models::NextRoundStart next_round()


Returns the next round start time in RFC 3339 format

### Parameters

This endpoint does not need any parameter.

### Return type

[**models::NextRoundStart**](NextRoundStart.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## offboard_all

> models::OffboardResult offboard_all(offboard_all_request)


Creates a new round participation to offboard all VTXOs

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**offboard_all_request** | [**OffboardAllRequest**](OffboardAllRequest.md) |  | [required] |

### Return type

[**models::OffboardResult**](OffboardResult.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## offboard_vtxos

> models::OffboardResult offboard_vtxos(offboard_vtxos_request)


Creates a new round participation to offboard the given VTXOs

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**offboard_vtxos_request** | [**OffboardVtxosRequest**](OffboardVtxosRequest.md) |  | [required] |

### Return type

[**models::OffboardResult**](OffboardResult.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## peak_address

> models::ArkAddressResponse peak_address(index)


Returns the Ark address at the given index. The address must have been already derived before using the /addresses/next endpoint.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**index** | **i32** | Index for the address. | [required] |

### Return type

[**models::ArkAddressResponse**](ArkAddressResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## pending_rounds

> Vec<models::PendingRoundInfo> pending_rounds()


Returns all the wallet ongoing round participations

### Parameters

This endpoint does not need any parameter.

### Return type

[**Vec<models::PendingRoundInfo>**](PendingRoundInfo.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## refresh_all

> models::PendingRoundInfo refresh_all()


Creates a new round participation to refresh all VTXOs

### Parameters

This endpoint does not need any parameter.

### Return type

[**models::PendingRoundInfo**](PendingRoundInfo.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## refresh_counterparty

> models::PendingRoundInfo refresh_counterparty()


Creates a new round participation to refresh VTXOs marked with counterparty

### Parameters

This endpoint does not need any parameter.

### Return type

[**models::PendingRoundInfo**](PendingRoundInfo.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## refresh_vtxos

> models::PendingRoundInfo refresh_vtxos(refresh_request)


Creates a new round participation to refresh the given VTXOs

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**refresh_request** | [**RefreshRequest**](RefreshRequest.md) |  | [required] |

### Return type

[**models::PendingRoundInfo**](PendingRoundInfo.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## send

> models::SendResponse send(send_request)


Sends a payment to the given destination. The destination can be an Ark address, a BOLT11-invoice, LNURL or a lightning address

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**send_request** | [**SendRequest**](SendRequest.md) |  | [required] |

### Return type

[**models::SendResponse**](SendResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## send_onchain

> models::OffboardResult send_onchain(send_onchain_request)


Creates a new round participation to send a payment onchain from ark round

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**send_onchain_request** | [**SendOnchainRequest**](SendOnchainRequest.md) |  | [required] |

### Return type

[**models::OffboardResult**](OffboardResult.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## sync

> sync()


Syncs the wallet

### Parameters

This endpoint does not need any parameter.

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## vtxos

> Vec<models::WalletVtxoInfo> vtxos(all)


Returns all the wallet VTXOs

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**all** | Option<**bool**> | Return all VTXOs regardless of their state. If not provided, returns only non-spent VTXOs. |  |

### Return type

[**Vec<models::WalletVtxoInfo>**](WalletVtxoInfo.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

