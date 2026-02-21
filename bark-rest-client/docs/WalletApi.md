# \WalletApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**address**](WalletApi.md#address) | **POST** /api/v1/wallet/addresses/next | Generate Ark address
[**ark_info**](WalletApi.md#ark_info) | **GET** /api/v1/wallet/ark-info | Get Ark server info
[**balance**](WalletApi.md#balance) | **GET** /api/v1/wallet/balance | Get wallet balance
[**connected**](WalletApi.md#connected) | **GET** /api/v1/wallet/connected | Check server connection
[**create_wallet**](WalletApi.md#create_wallet) | **POST** /api/v1/wallet/create | Create a wallet
[**history**](WalletApi.md#history) | **GET** /api/v1/wallet/history | Get wallet history
[**import_vtxo**](WalletApi.md#import_vtxo) | **POST** /api/v1/wallet/import-vtxo | Import a VTXO
[**movements**](WalletApi.md#movements) | **GET** /api/v1/wallet/movements | List movements (deprecated)
[**next_round**](WalletApi.md#next_round) | **GET** /api/v1/wallet/next-round | Get next round time
[**offboard_all**](WalletApi.md#offboard_all) | **POST** /api/v1/wallet/offboard/all | Offboard all VTXOs
[**offboard_vtxos**](WalletApi.md#offboard_vtxos) | **POST** /api/v1/wallet/offboard/vtxos | Offboard specific VTXOs
[**peak_address**](WalletApi.md#peak_address) | **GET** /api/v1/wallet/addresses/index/{index} | Get Ark address by index
[**pending_rounds**](WalletApi.md#pending_rounds) | **GET** /api/v1/wallet/rounds | List round participations
[**refresh_all**](WalletApi.md#refresh_all) | **POST** /api/v1/wallet/refresh/all | Refresh all VTXOs
[**refresh_counterparty**](WalletApi.md#refresh_counterparty) | **POST** /api/v1/wallet/refresh/counterparty | Refresh received VTXOs
[**refresh_vtxos**](WalletApi.md#refresh_vtxos) | **POST** /api/v1/wallet/refresh/vtxos | Refresh specific VTXOs
[**send**](WalletApi.md#send) | **POST** /api/v1/wallet/send | Send a payment
[**send_onchain**](WalletApi.md#send_onchain) | **POST** /api/v1/wallet/send-onchain | Send on-chain from Ark balance
[**sync**](WalletApi.md#sync) | **POST** /api/v1/wallet/sync | Sync wallet
[**vtxos**](WalletApi.md#vtxos) | **GET** /api/v1/wallet/vtxos | List VTXOs



## address

> models::ArkAddressResponse address()
Generate Ark address

Generates a new Ark receiving address. Each call returns the next unused address from the wallet's HD keychain.

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
Get Ark server info

Returns the Ark server's configuration parameters, including network, public key, round interval, VTXO expiry and exit deltas, fee settings, and Lightning support details.

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
Get wallet balance

Returns the wallet balance broken down by category: spendable sats available for immediate use, sats pending in an Ark round, sats locked in outgoing or incoming Lightning payments, sats awaiting board confirmation, and sats in a pending exit. The balance is computed from local state, which the background daemon keeps reasonably fresh (Lightning syncs every second, mailbox and boards every 30 seconds). For the most up-to-date figures, call `sync` before this endpoint.

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
Check server connection

Checks whether the wallet has an active connection to the Ark server. Returns `true` if the wallet can reach the server and retrieve its configuration, `false` otherwise. The background daemon checks the server connection every second, so this reflects the most recent known state.

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
Create a wallet

Creates a new wallet with the specified Ark server and chain source configuration. Fails if a wallet already exists. Returns the wallet fingerprint on success.

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
Get wallet history

Returns the full history of wallet movements ordered from newest to oldest. A movement represents any wallet operation that affects VTXOs—an arkoor send or receive, Lightning send or receive, board, offboard, or refresh. Each entry records which VTXOs were consumed and produced, the effective balance change (if any), fees paid, and the operation status.

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
Import a VTXO

Imports hex-encoded serialized VTXOs into the wallet. Validates that each VTXO is anchored on-chain, owned by this wallet, and has not expired. Useful for restoring VTXOs after database loss or re-importing from the server mailbox. The operation is idempotent.

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
List movements (deprecated)

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
Get next round time

Queries the Ark server for the next scheduled round start time and returns it in RFC 3339 format.

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
Offboard all VTXOs

Cooperatively moves all spendable VTXOs off the Ark protocol to an on-chain address. Each VTXO is offboarded in full—partial amounts are not supported. The on-chain transaction fee is deducted from the total, and the remaining amount is sent to the destination. If no address is specified, the wallet generates a new on-chain address. To send a specific amount on-chain, use `send-onchain` instead.

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
Offboard specific VTXOs

Cooperatively moves the specified VTXOs off the Ark protocol to an on-chain address. Each VTXO is offboarded in full—partial amounts are not supported. The on-chain transaction fee is deducted from the total, and the remaining amount is sent to the destination. If no address is specified, the wallet generates a new on-chain address. To send a specific amount on-chain, use `send-onchain` instead.

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
Get Ark address by index

Returns a previously generated Ark address by its derivation index. Only addresses that have already been generated are available.

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
List round participations

Returns all active round participations and their current status. A round participation is created when you call one of the `refresh` endpoints and persists until the round's funding transaction is confirmed on-chain (2 confirmations on mainnet, 1 on testnet). The list can contain multiple entries—for example, a previous round awaiting on-chain confirmation alongside a newly submitted round waiting for the next server round to start. Confirmed and failed rounds are removed automatically by the background daemon.

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
Refresh all VTXOs

Registers all spendable VTXOs for refresh in the next Ark round. The input VTXOs are locked immediately and will be forfeited once the round completes, yielding new VTXOs with a fresh expiry. The background daemon automatically participates in the round and progresses it to completion. Use the `rounds` endpoint to track progress.

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
Refresh received VTXOs

Registers all out-of-round VTXOs held by the wallet for refresh in the next Ark round. Refreshing replaces out-of-round VTXOs under arkoor trust assumptions with trustless, in-round VTXOs. Out-of-round VTXOs whose entire transaction chain originates from your own in-round VTXOs are excluded. The background daemon automatically participates in the round and progresses it to completion. Use the `rounds` endpoint to track progress.

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
Refresh specific VTXOs

Registers the specified VTXOs for refresh in the next Ark round. The input VTXOs are locked immediately and will be forfeited once the round completes, yielding new VTXOs with a fresh expiry. The background daemon automatically participates in the round and progresses it to completion. Use the `rounds` endpoint to track progress.

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
Send a payment

Sends an Ark or Lightning payment to the specified destination. Accepts an Ark address, BOLT11 invoice, BOLT12 offer, or Lightning address. Ark address payments are settled instantly via an out-of-round (arkoor) transaction. The `amount_sat` field is required for Ark addresses and Lightning addresses but optional for invoices and offers that already encode an amount. Comments are only supported for Lightning addresses. To send to an on-chain bitcoin address, use `send-onchain` instead.

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
Send on-chain from Ark balance

Sends the specified amount to an on-chain address using the wallet's off-chain Ark balance. The on-chain transaction fee is paid on top of the specified amount. Internally creates an out-of-round transaction to consolidate VTXOs into the exact amount needed, then cooperatively sends the on-chain payment via the Ark server. To offboard entire VTXOs without specifying an amount, use `offboard/vtxos` or `offboard/all` instead.

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
Sync wallet

Triggers an immediate sync of the wallet's off-chain state. Updates on-chain fee rates, processes incoming arkoor payments, resolves outgoing and incoming Lightning payments, and progresses pending rounds and boards toward confirmation. The background daemon already runs these operations automatically (e.g., Lightning every second, mailbox and boards every 30 seconds), but calling `sync` forces all of them to run immediately.

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
List VTXOs

Returns VTXOs held by the wallet, including their state and expiry information. By default returns only non-spent VTXOs. Set `all=true` to include all VTXOs regardless of state.

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

