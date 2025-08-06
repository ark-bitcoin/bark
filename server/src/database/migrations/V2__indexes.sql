
CREATE INDEX all_arkoor_mailbox_pubkey_ix ON all_arkoor_mailbox(pubkey) WHERE deleted_at IS NULL;
CREATE INDEX all_vtxo_board_swept_expiry_ix ON all_vtxo(board_swept, expiry) WHERE deleted_at IS NULL;
CREATE INDEX all_round_expiry_ix ON all_round(expiry) WHERE deleted_at IS NULL;
