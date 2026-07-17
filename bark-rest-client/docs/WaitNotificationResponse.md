# WaitNotificationResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**last_pushed_at** | Option<**String**> | The timestamp of the last notification pushed to the client. | [optional]
**notifications** | [**Vec<models::WalletNotification>**](WalletNotification.md) | Notifications received during the long-poll window. Empty if the timeout elapsed without any notifications. Sorted by timestamp in ascending order. | 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


