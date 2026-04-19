# CreateWalletRequest

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**ark_server** | Option<**String**> | The Ark server to use for the wallet. Optional when a config.toml already exists in the datadir. | [optional]
**birthday_height** | Option<**i32**> | An optional birthday height to start syncing the wallet from | [optional]
**chain_source** | Option<[**models::ChainSourceConfig**](ChainSourceConfig.md)> | The chain source to use for the wallet. Optional when a config.toml already exists in the datadir. | [optional]
**mnemonic** | Option<**String**> | The optional mnemonic to use for the wallet | [optional]
**network** | [**models::BarkNetwork**](BarkNetwork.md) | The network to use for the wallet | 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


