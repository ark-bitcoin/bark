# \NotificationsApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**wait_notification**](NotificationsApi.md#wait_notification) | **GET** /api/v1/notifications/wait | Long-poll for wallet notifications
[**websocket_ticket**](NotificationsApi.md#websocket_ticket) | **GET** /api/v1/notifications/ws/ticket | Create a websocket ticket



## wait_notification

> models::WaitNotificationResponse wait_notification(since)
Long-poll for wallet notifications

Long-polls for wallet notifications. Returns all notifications received since the given timestamp. If no timestamp is provided, returns all notifications in the buffer. Returned notifications are sorted by timestamp in ascending order.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**since** | Option<**String**> | The timestamp to start waiting for notifications from. If not provided, returns all notifications in the buffer. |  |

### Return type

[**models::WaitNotificationResponse**](WaitNotificationResponse.md)

### Authorization

[bearer](../README.md#bearer)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## websocket_ticket

> String websocket_ticket()
Create a websocket ticket

Creates a single-use ticket that authenticates a websocket connection at `ws://<host>/api/v1/notifications/ws?ticket=<ticket>`. The ticket must be used within 10 minutes of creation; the resulting websocket connection is long-lived.

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

