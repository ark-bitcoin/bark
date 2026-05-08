-- Add 'unregistered' spend state.
--
-- Vtxos created by the server (e.g. arkoor outputs, lightning revoke
-- outputs) start in this state until the client has uploaded the signed
-- transaction chain via register_vtxo_transactions. While unregistered,
-- the vtxo is unspendable: check_spendable rejects it and every existing
-- mark_vtxos_* transition gates on 'spendable'.
ALTER TYPE spend_state ADD VALUE 'unregistered';
