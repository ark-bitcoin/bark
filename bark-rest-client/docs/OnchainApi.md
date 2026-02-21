# \OnchainApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**onchain_address**](OnchainApi.md#onchain_address) | **POST** /api/v1/onchain/addresses/next | Generate on-chain address
[**onchain_balance**](OnchainApi.md#onchain_balance) | **GET** /api/v1/onchain/balance | Get on-chain balance
[**onchain_drain**](OnchainApi.md#onchain_drain) | **POST** /api/v1/onchain/drain | Drain on-chain wallet
[**onchain_send**](OnchainApi.md#onchain_send) | **POST** /api/v1/onchain/send | Send on-chain payment
[**onchain_send_many**](OnchainApi.md#onchain_send_many) | **POST** /api/v1/onchain/send-many | Send to multiple addresses
[**onchain_sync**](OnchainApi.md#onchain_sync) | **POST** /api/v1/onchain/sync | Sync on-chain wallet
[**onchain_transactions**](OnchainApi.md#onchain_transactions) | **GET** /api/v1/onchain/transactions | List on-chain transactions
[**onchain_utxos**](OnchainApi.md#onchain_utxos) | **GET** /api/v1/onchain/utxos | List on-chain UTXOs



## onchain_address

> models::Address onchain_address()
Generate on-chain address

Generates a new on-chain receiving address. Each call returns the next unused address from the wallet's HD keychain.

### Parameters

This endpoint does not need any parameter.

### Return type

[**models::Address**](Address.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## onchain_balance

> models::OnchainBalance onchain_balance()
Get on-chain balance

Returns the current on-chain wallet balance, broken down by confirmation status. The `trusted_spendable_sat` field is the sum of `confirmed_sat` and `trusted_pending_sat`—the balance that can be safely spent without risk of double-spend.

### Parameters

This endpoint does not need any parameter.

### Return type

[**models::OnchainBalance**](OnchainBalance.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## onchain_drain

> models::Send onchain_drain(onchain_drain_request)
Drain on-chain wallet

Sends the entire on-chain wallet balance to the specified address. The recipient receives the full balance minus transaction fees. Broadcasts immediately at a fee rate targeting confirmation within three blocks and returns the transaction ID.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**onchain_drain_request** | [**OnchainDrainRequest**](OnchainDrainRequest.md) |  | [required] |

### Return type

[**models::Send**](Send.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## onchain_send

> models::Send onchain_send(onchain_send_request)
Send on-chain payment

Sends the specified amount to an on-chain address. Broadcasts the transaction immediately at a fee rate targeting confirmation within three blocks and returns the transaction ID.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**onchain_send_request** | [**OnchainSendRequest**](OnchainSendRequest.md) |  | [required] |

### Return type

[**models::Send**](Send.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## onchain_send_many

> models::Send onchain_send_many(onchain_send_many_request)
Send to multiple addresses

Batches multiple payments into a single on-chain transaction. Each destination is formatted as `address:amount`. Broadcasts the transaction immediately at a fee rate targeting confirmation within three blocks and returns the transaction ID.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**onchain_send_many_request** | [**OnchainSendManyRequest**](OnchainSendManyRequest.md) |  | [required] |

### Return type

[**models::Send**](Send.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## onchain_sync

> onchain_sync()
Sync on-chain wallet

Syncs the on-chain wallet state with the chain source. Fetches new blocks and transactions, updates the UTXO set, and re-submits any stale unconfirmed transactions to the mempool.

### Parameters

This endpoint does not need any parameter.

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## onchain_transactions

> Vec<models::TransactionInfo> onchain_transactions()
List on-chain transactions

Returns all on-chain wallet transactions, ordered from oldest to newest.

### Parameters

This endpoint does not need any parameter.

### Return type

[**Vec<models::TransactionInfo>**](TransactionInfo.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## onchain_utxos

> Vec<models::UtxoInfo> onchain_utxos()
List on-chain UTXOs

Returns all UTXOs in the on-chain wallet. Each entry includes the outpoint, amount, and confirmation height (if confirmed).

### Parameters

This endpoint does not need any parameter.

### Return type

[**Vec<models::UtxoInfo>**](UtxoInfo.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

