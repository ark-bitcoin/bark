# \NotificationsApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**websocket_ticket**](NotificationsApi.md#websocket_ticket) | **GET** /api/v1/notifications/ws/ticket | Create a new websocket ticket. You can call then `ws://<host>/api/v1/notifications/ws?ticket=<ticket>` to subscribe to notifications



## websocket_ticket

> String websocket_ticket()
Create a new websocket ticket. You can call then `ws://<host>/api/v1/notifications/ws?ticket=<ticket>` to subscribe to notifications

### Parameters

This endpoint does not need any parameter.

### Return type

**String**

### Authorization

[bearer](../README.md#bearer)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: text/plain

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

