# \FeesApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**board_fee**](FeesApi.md#board_fee) | **GET** /api/v1/fees/board | Estimate board fee
[**lightning_receive_fee**](FeesApi.md#lightning_receive_fee) | **GET** /api/v1/fees/lightning/receive | Estimate Lightning receive fee
[**lightning_send_fee**](FeesApi.md#lightning_send_fee) | **GET** /api/v1/fees/lightning/pay | Estimate Lightning send fee
[**offboard_all_fee**](FeesApi.md#offboard_all_fee) | **GET** /api/v1/fees/offboard-all | Estimate offboard-all fee
[**onchain_fee_rates**](FeesApi.md#onchain_fee_rates) | **GET** /api/v1/fees/onchain | Get on-chain fee rates
[**send_onchain_fee**](FeesApi.md#send_onchain_fee) | **GET** /api/v1/fees/send-onchain | Estimate send-onchain fee



## board_fee

> models::FeeEstimateResponse board_fee(amount_sat)
Estimate board fee

Estimates the Ark protocol fee for boarding the specified amount of on-chain bitcoin. The net amount is what the user receives as a VTXO. Does not include the on-chain transaction fee for the board anchor transaction.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**amount_sat** | **i64** | The amount in satoshis to board | [required] |

### Return type

[**models::FeeEstimateResponse**](FeeEstimateResponse.md)

### Authorization

[bearer](../README.md#bearer)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## lightning_receive_fee

> models::FeeEstimateResponse lightning_receive_fee(amount_sat)
Estimate Lightning receive fee

Estimates the fee for receiving the specified amount over Lightning. The gross amount is the Lightning payment amount, and the net amount is what the user receives as a VTXO after the Ark server deducts its fee.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**amount_sat** | **i64** | The amount in satoshis to receive over Lightning | [required] |

### Return type

[**models::FeeEstimateResponse**](FeeEstimateResponse.md)

### Authorization

[bearer](../README.md#bearer)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## lightning_send_fee

> models::FeeEstimateResponse lightning_send_fee(amount_sat)
Estimate Lightning send fee

Estimates the fee for sending the specified amount over Lightning. The net amount is what the recipient receives. The fee depends on the VTXOs selected and their expiry. If the wallet has insufficient funds, returns a worst-case fee estimate assuming the user acquires enough funds to cover the payment.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**amount_sat** | **i64** | The amount in satoshis to send over Lightning | [required] |

### Return type

[**models::FeeEstimateResponse**](FeeEstimateResponse.md)

### Authorization

[bearer](../README.md#bearer)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## offboard_all_fee

> models::FeeEstimateResponse offboard_all_fee(address)
Estimate offboard-all fee

Estimates the fee for offboarding the entire Ark balance to the given on-chain address. The gross amount is the total spendable balance, and the net amount is what the user receives on-chain after fees. The fee depends on the destination address type, current fee rates, and VTXO expiry.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**address** | **String** | The destination Bitcoin address | [required] |

### Return type

[**models::FeeEstimateResponse**](FeeEstimateResponse.md)

### Authorization

[bearer](../README.md#bearer)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## onchain_fee_rates

> models::OnchainFeeRatesResponse onchain_fee_rates()
Get on-chain fee rates

Returns the current mempool fee rates from the chain source at three confirmation targets: fast (~1 block), regular (~3 blocks), and slow (~6 blocks). Rates are in sat/vB, rounded up.

### Parameters

This endpoint does not need any parameter.

### Return type

[**models::OnchainFeeRatesResponse**](OnchainFeeRatesResponse.md)

### Authorization

[bearer](../README.md#bearer)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## send_onchain_fee

> models::FeeEstimateResponse send_onchain_fee(amount_sat, address)
Estimate send-onchain fee

Estimates the total fee for sending bitcoin from the Ark wallet to an on-chain address. The fee depends on the destination address type and current fee rates. The gross amount is what the user pays (including VTXOs spent), and the net amount is what the recipient receives on-chain.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**amount_sat** | **i64** | The amount in satoshis to send on-chain | [required] |
**address** | **String** | The destination Bitcoin address | [required] |

### Return type

[**models::FeeEstimateResponse**](FeeEstimateResponse.md)

### Authorization

[bearer](../README.md#bearer)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

