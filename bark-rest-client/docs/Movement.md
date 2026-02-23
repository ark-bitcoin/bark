# Movement

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**effective_balance_sat** | **i64** | How much the wallet balance actually changed by. Positive numbers indicate an increase and negative numbers indicate a decrease. This is often inclusive of applicable fees, and it should be the most accurate number. | 
**exited_vtxos** | **Vec<String>** | A list of IDs for VTXOs that were marked for unilateral exit as a result of this movement. This could happen for many reasons, e.g. an unsuccessful lightning payment which can't be revoked but is about to expire. VTXOs listed here will result in a reduction of spendable balance due to the VTXOs being managed by the [bark::exit::Exit] system. | 
**id** | **i32** | The internal ID of the movement. | 
**input_vtxos** | **Vec<String>** | A list of [Vtxo](ark::Vtxo) IDs that were consumed by this movement and are either locked or unavailable. | 
**intended_balance_sat** | **i64** | How much the movement was expected to increase or decrease the balance by. This is always an estimate and often discounts any applicable fees. | 
**metadata** | Option<[**std::collections::HashMap<String, serde_json::Value>**](serde_json::Value.md)> | Miscellaneous metadata for the movement. This is JSON containing arbitrary information as defined by the subsystem that created the movement. | [optional]
**offchain_fee_sat** | **i64** | How much the movement cost the user in offchain fees. If there are applicable onchain fees they will not be included in this value but, depending on the subsystem, could be found in the metadata. | 
**output_vtxos** | **Vec<String>** | A list of IDs for new VTXOs that were produced as a result of this movement. Often change VTXOs will be found here for outbound actions unless this was an inbound action. | 
**received_on** | [**Vec<models::MovementDestination>**](MovementDestination.md) | Describes the means by which the wallet received funds in this movement. This could include BOLT11 invoices or other useful data. | 
**sent_to** | [**Vec<models::MovementDestination>**](MovementDestination.md) | A list of external recipients that received funds from this movement. | 
**status** | [**models::MovementStatus**](MovementStatus.md) | The status of the movement. | 
**subsystem** | [**models::MovementSubsystem**](MovementSubsystem.md) | Contains information about the subsystem that created the movement as well as the purpose of the movement. | 
**time** | [**models::MovementTimestamp**](MovementTimestamp.md) | Contains the times at which the movement was created, updated and completed. | 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


