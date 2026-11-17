# \NwcApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**add_relay**](NwcApi.md#add_relay) | **POST** /api/v1/nwc/relays | Add a NWC relay
[**create_connection**](NwcApi.md#create_connection) | **POST** /api/v1/nwc/connections | Create a NWC connection
[**list_connections**](NwcApi.md#list_connections) | **GET** /api/v1/nwc/connections | List NWC connections
[**list_relays**](NwcApi.md#list_relays) | **GET** /api/v1/nwc/relays | List NWC relays
[**remove_relay**](NwcApi.md#remove_relay) | **DELETE** /api/v1/nwc/relays/{relay} | Remove a NWC relay
[**revoke_connection**](NwcApi.md#revoke_connection) | **DELETE** /api/v1/nwc/connections/{client_pubkey} | Revoke a NWC connection



## add_relay

> models::NwcRelaysResponse add_relay(nwc_relay_request)
Add a NWC relay

Adds a nostr relay and restarts every connection's service on the new set. The change is stored with the connections in nwc.json, so it survives a restart. Adding a relay that is already configured changes nothing.  Existing connection URIs keep the relays they were created with, so an app only learns of the new relay from a new connection.  The NWC endpoints respond with 404 when barkd was built without NWC support or has no wallet loaded.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**nwc_relay_request** | [**NwcRelayRequest**](NwcRelayRequest.md) |  | [required] |

### Return type

[**models::NwcRelaysResponse**](NwcRelaysResponse.md)

### Authorization

[bearer](../README.md#bearer)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## create_connection

> models::NwcConnectionResponse create_connection(nwc_connection_request)
Create a NWC connection

Creates a Nostr Wallet Connect connection and returns the `nostr+walletconnect://` URI to hand to an app. The URI contains a secret that is not stored and is returned only once; a lost URI has to be revoked and recreated.  Every method bark supports is allowed unless it is set to `false` in `methods`, so a connection created without `methods` may call all of them, `pay_invoice` included.  The URI names the relays configured at creation, so at least one relay has to be added first (see `POST /api/v1/nwc/relays`).  The NWC endpoints respond with 404 when barkd was built without NWC support or has no wallet loaded.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**nwc_connection_request** | [**NwcConnectionRequest**](NwcConnectionRequest.md) |  | [required] |

### Return type

[**models::NwcConnectionResponse**](NwcConnectionResponse.md)

### Authorization

[bearer](../README.md#bearer)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## list_connections

> models::NwcConnectionListResponse list_connections()
List NWC connections

Lists every Nostr Wallet Connect connection with its permitted methods. Connection secrets are never returned.  The NWC endpoints respond with 404 when barkd was built without NWC support or has no wallet loaded.

### Parameters

This endpoint does not need any parameter.

### Return type

[**models::NwcConnectionListResponse**](NwcConnectionListResponse.md)

### Authorization

[bearer](../README.md#bearer)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## list_relays

> models::NwcRelaysResponse list_relays()
List NWC relays

Lists the nostr relays that Nostr Wallet Connect is served on.  The NWC endpoints respond with 404 when barkd was built without NWC support or has no wallet loaded.

### Parameters

This endpoint does not need any parameter.

### Return type

[**models::NwcRelaysResponse**](NwcRelaysResponse.md)

### Authorization

[bearer](../README.md#bearer)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## remove_relay

> models::NwcRelaysResponse remove_relay(relay)
Remove a NWC relay

Removes a nostr relay and restarts every connection's service on the remaining ones. The change is stored with the connections in nwc.json, so it survives a restart.  An app only reaches the wallet through the relays in its connection URI, so removing all of them cuts it off until it is given a new connection.  The NWC endpoints respond with 404 when barkd was built without NWC support or has no wallet loaded.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**relay** | **String** | The relay url, percent-encoded | [required] |

### Return type

[**models::NwcRelaysResponse**](NwcRelaysResponse.md)

### Authorization

[bearer](../README.md#bearer)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## revoke_connection

> revoke_connection(client_pubkey)
Revoke a NWC connection

Revokes a Nostr Wallet Connect connection and stops serving it. The app loses access immediately; requests it sends afterwards go unanswered rather than being refused, because the service it was talking to no longer exists.  The NWC endpoints respond with 404 when barkd was built without NWC support or has no wallet loaded.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**client_pubkey** | **String** | The connection's client public key | [required] |

### Return type

 (empty response body)

### Authorization

[bearer](../README.md#bearer)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

