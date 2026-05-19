# WalletTxInfo

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**balance_change_sat** | **i64** | Net change to the wallet's balance: `received - sent` over wallet-owned outputs. Positive for inbound, negative for outbound, zero for self-spends with no net change. | 
**confirmation** | Option<[**models::BlockRef**](BlockRef.md)> | `Some` when the transaction is mined; `None` while still in the mempool. | [optional]
**onchain_fee_sat** | Option<**i64**> | Total fee paid by the transaction, when known. `None` for txs whose foreign prevouts BDK has not indexed (e.g. inbound payments observed via the bitcoind-rpc sync path; esplora sync always populates prevouts). | [optional]
**tx** | **String** |  | 
**txid** | **String** |  | 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


