//! A board takes two gRPC calls:
//!
//! - `request_board_cosign`: the client sends the board amount, its utxo and the
//!   funding tx that creates it. The server checks the request and signs the exit
//!   tx of the board.
//! - `register_board_vtxo`: once the funding tx has enough confirmations, the
//!   client sends the signed vtxo. From then on the server knows the vtxo and it
//!   can be spent.

use std::collections::HashMap;
use std::str::FromStr;

use bitcoin::{absolute, transaction, Address, Amount, Network, OutPoint, ScriptBuf, Sequence};
use bitcoin::{Transaction, TxIn, TxOut, Txid, Witness};
use bitcoin::secp256k1::{Keypair, PublicKey, rand::thread_rng};
use bitcoincore_rpc::RpcApi;
use bitcoincore_rpc::json::CreateRawTransactionInput;
use server::database::Db;
use server_log::{ArkFeeRecorded, BoardAttemptBlockedAddress};
use server_rpc::protos;

use ark::{ProtocolEncoding, SECP};
use ark::attestations::VtxoStatusAttestation;
use ark::board::{state, BoardBuilder, BoardCosignResponse};
use ark::fees::{BoardFees, PpmFeeRate};
use ark::musig;

use bitcoin_ext::{BlockHeight, P2TR_DUST_SAT};

use ark_testing::{sat, TestContext};

#[tokio::test]
async fn board_validates_requests_and_replays_retries() {
	let ctx = TestContext::new("server/board_validates_requests_and_replays_retries").await;
	let blocklist_path = ctx.datadir.join("blocklist.txt");
	tokio::fs::write(&blocklist_path, "").await.unwrap();
	// Share the bitcoind, so txs reach the server without waiting for relay.
	let cfg_blocklist_path = blocklist_path.clone();
	let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).no_vtxo_pool().cfg(move |cfg| {
		cfg.bitcoin_address_blocklist = Some(cfg_blocklist_path);
		// No minimum of its own, so the dust limit is the minimum.
		cfg.min_board_amount = Amount::ZERO;
		cfg.max_board_amount = Some(sat(500_000));
		// 100 sat + 0.1%, so a board of 100_000 sat pays 200 sat and one of 500_000 sat pays 600 sat.
		cfg.fees.board = BoardFees {
			min_fee: Amount::ZERO,
			base_fee: sat(100),
			ppm: PpmFeeRate(1_000),
		};
	}).create().await;
	let info = srv.ark_info().await;
	let mut rpc = srv.get_public_rpc().await;

	let tip = async || BlockHeight::new(u32::try_from(ctx.bitcoind().get_block_count().await).unwrap());
	// Mines `n` blocks on top of `txid` and waits until the server has seen them.
	let confirm = async |txid: Txid, n: u32| {
		ctx.bitcoind().await_transaction(txid).await;
		ctx.bitcoind().generate(n).await;
		srv.wait_for_sync_height(tip().await).await;
	};
	let new_board = |server_pubkey: PublicKey, expiry: BlockHeight| {
		let key = Keypair::new(&SECP, &mut thread_rng());
		let builder = BoardBuilder::new(
			key.public_key(), expiry, server_pubkey, info.vtxo_exit_delta,
		).unwrap();
		(key, builder)
	};
	// Adds the address of `script` to the blocklist.
	let block = async |script: &ScriptBuf| {
		let address = Address::from_script(script, Network::Regtest).unwrap();
		let mut blocklist = tokio::fs::read_to_string(&blocklist_path).await.unwrap();
		blocklist.push_str(&format!("{address}\n"));
		tokio::fs::write(&blocklist_path, blocklist).await.unwrap();
		srv.get_blocklist_rpc().await.reload_blocklist(protos::Empty {}).await.unwrap();
		address
	};
	// Pays `amount` to the funding output of `builder`. Returns the funding tx and the board utxo.
	let fund = async |builder: &BoardBuilder<state::Preparing>, amount: Amount| {
		let script = builder.funding_script_pubkey();
		let address = Address::from_script(&script, Network::Regtest).unwrap();
		let txid = ctx.bitcoind().fund_addr(&address, amount).await;
		let funding_tx = ctx.bitcoind().await_transaction(txid).await;
		let vout = funding_tx.output.iter().position(|o| o.script_pubkey == script).unwrap();
		let utxo = OutPoint::new(txid, u32::try_from(vout).unwrap());
		(funding_tx, utxo)
	};
	// Like `fund` for 100_000 sat, but the funding tx spends a utxo of `source`. The
	// rest of the utxo goes to fees.
	let fund_from = async |source: &Address, builder: &BoardBuilder<state::Preparing>| {
		let client = ctx.bitcoind().sync_client();
		let source_txid = ctx.bitcoind().fund_addr(source, sat(110_000)).await;
		let source_tx = ctx.bitcoind().await_transaction(source_txid).await;
		let source_vout = source_tx.output.iter()
			.position(|o| o.script_pubkey == source.script_pubkey()).unwrap();
		let input = CreateRawTransactionInput {
			txid: source_txid,
			vout: u32::try_from(source_vout).unwrap(),
			sequence: None,
		};
		let script = builder.funding_script_pubkey();
		let address = Address::from_script(&script, Network::Regtest).unwrap();
		let outputs = HashMap::from([(address.to_string(), sat(100_000))]);
		let raw_tx = client.create_raw_transaction(&[input], &outputs, None, None).unwrap();
		let signed_tx = client.sign_raw_transaction_with_wallet(&raw_tx, None, None)
			.unwrap().transaction().unwrap();
		let txid = client.send_raw_transaction(&signed_tx).unwrap();
		let funding_tx = ctx.bitcoind().await_transaction(txid).await;
		let vout = funding_tx.output.iter().position(|o| o.script_pubkey == script).unwrap();
		(funding_tx, OutPoint::new(txid, u32::try_from(vout).unwrap()))
	};
	let cosign_request = |key: &Keypair, nonce: &musig::PublicNonce, expiry: BlockHeight, amount: Amount, utxo: OutPoint, funding_tx: &Transaction| {
		protos::BoardCosignRequest {
			owner_mailbox: None,
			amount: amount.to_sat(),
			utxo: utxo.serialize(),
			expiry_height: expiry.to_u32(),
			user_pubkey: key.public_key().serialize().to_vec(),
			pub_nonce: nonce.serialize().to_vec(),
			funding_tx: bitcoin::consensus::serialize(funding_tx),
		}
	};

	// Board a utxo and register it
	let board_vtxo = Box::pin(async {
		// A board of 500_000 sat, the max_board_amount. The fee leaves a vtxo of 499_400 sat.
		let tip = tip().await;
		let expiry = tip + info.vtxo_lifetime;
		let (key, builder) = new_board(info.server_pubkey, expiry);
		let (funding_tx, utxo) = fund(&builder, sat(500_000)).await;
		let builder = builder.set_funding_details(sat(500_000), sat(600), utxo).unwrap()
			.generate_user_nonces();
		let req = cosign_request(&key, builder.user_pub_nonce(), expiry, sat(500_000), utxo, &funding_tx);

		// Below the dust limit
		let bad = protos::BoardCosignRequest { amount: P2TR_DUST_SAT - 1, ..req.clone() };
		let err = rpc.request_board_cosign(bad).await.unwrap_err();
		assert_eq!(err.code(), tonic::Code::InvalidArgument, "{err}");
		assert!(err.message().contains("board amount must be at least 0.00000330 BTC"), "{err}");

		// Over max_board_amount
		let bad = protos::BoardCosignRequest { amount: 500_001, ..req.clone() };
		let err = rpc.request_board_cosign(bad).await.unwrap_err();
		assert_eq!(err.code(), tonic::Code::InvalidArgument, "{err}");
		assert!(err.message().contains("board amount exceeds limit of 0.00500000 BTC"), "{err}");

		// Expires 65_536 blocks after the tip, far beyond the vtxo lifetime
		let bad = protos::BoardCosignRequest { expiry_height: tip.to_u32() + 65_536, ..req.clone() };
		let err = rpc.request_board_cosign(bad).await.unwrap_err();
		assert_eq!(err.code(), tonic::Code::InvalidArgument, "{err}");
		assert!(err.message().contains("is too high"), "{err}");

		// The lifetime is the highest multiple of 65_536 blocks the server accepts as a height
		let offset = ark::vtxo::policy::MAX_BLOCK_HEIGHT.to_u32() - tip.to_u32();
		let bad = protos::BoardCosignRequest { expiry_height: tip.to_u32() + (offset - offset % 65_536), ..req.clone() };
		let err = rpc.request_board_cosign(bad).await.unwrap_err();
		assert_eq!(err.code(), tonic::Code::InvalidArgument, "{err}");
		assert!(err.message().contains("is too high"), "{err}");

		// Sends no funding tx
		let bad = protos::BoardCosignRequest { funding_tx: vec![], ..req.clone() };
		let err = rpc.request_board_cosign(bad).await.unwrap_err();
		assert_eq!(err.code(), tonic::Code::InvalidArgument, "{err}");

		// The funding tx has no output at the utxo's vout
		let vout = u32::try_from(funding_tx.output.len()).unwrap();
		let bad = protos::BoardCosignRequest { utxo: OutPoint::new(utxo.txid, vout).serialize(), ..req.clone() };
		let err = rpc.request_board_cosign(bad).await.unwrap_err();
		assert_eq!(err.code(), tonic::Code::InvalidArgument, "{err}");
		assert!(err.message().contains("board outpoint does not match funding tx (vout)"), "{err}");

		// The utxo is an output of another tx
		let other = OutPoint::new(funding_tx.input[0].previous_output.txid, 0);
		let bad = protos::BoardCosignRequest { utxo: other.serialize(), ..req.clone() };
		let err = rpc.request_board_cosign(bad).await.unwrap_err();
		assert_eq!(err.code(), tonic::Code::InvalidArgument, "{err}");
		assert!(err.message().contains("board outpoint does not match funding tx (txid)"), "{err}");

		// Claims a different amount than the funding output pays
		let bad = protos::BoardCosignRequest { amount: 499_777, ..req.clone() };
		let err = rpc.request_board_cosign(bad).await.unwrap_err();
		assert_eq!(err.code(), tonic::Code::InvalidArgument, "{err}");
		assert!(err.message().contains("does not match funding tx output value"), "{err}");

		// A client that lost the first response sends the same request again.
		let cosign = rpc.request_board_cosign(req.clone()).await.unwrap().into_inner();
		let retry = rpc.request_board_cosign(req).await.unwrap().into_inner();
		// Both responses sign the client's exit tx.
		let cosign = BoardCosignResponse::try_from(cosign).unwrap();
		let retry = BoardCosignResponse::try_from(retry).unwrap();
		assert!(builder.verify_cosign_response(&cosign));
		assert!(builder.verify_cosign_response(&retry));
		let vtxo = builder.build_vtxo(&cosign, &key).unwrap();
		let register = protos::BoardVtxoRequest { board_vtxo: vtxo.serialize() };
		let register_chain = protos::RegisterVtxoTransactionsRequest { vtxos: vec![vtxo.serialize()] };

		// The server knows the vtxo only once its board is registered
		let err = rpc.register_vtxo_transactions(register_chain).await.unwrap_err();
		assert_eq!(err.code(), tonic::Code::NotFound, "{err}");
		assert!(err.message().contains("vtxo not found"), "{err}");

		// The funding tx is unconfirmed. The client may retry: the funding tx confirms later.
		let err = rpc.register_board_vtxo(register.clone()).await.unwrap_err();
		assert_eq!(err.code(), tonic::Code::Internal, "{err}");
		assert!(err.message().contains("unconfirmed"), "{err}");

		// The funding tx is one confirmation short
		let required = u32::try_from(srv.config().required_board_confirmations).unwrap();
		confirm(utxo.txid, required - 1).await;
		let err = rpc.register_board_vtxo(register.clone()).await.unwrap_err();
		assert_eq!(err.code(), tonic::Code::Internal, "{err}");
		assert!(err.message().contains(&format!("requires {required}")), "{err}");

		// With enough confirmations the board registers, and the server records its fee.
		confirm(utxo.txid, 1).await;
		let mut fees = srv.subscribe_log::<ArkFeeRecorded>();
		rpc.register_board_vtxo(register.clone()).await.unwrap();
		let fee = fees.recv().await.unwrap();
		assert_eq!(fee.op_type, "board");
		assert_eq!(fee.net_fee_sat, 600);
		assert_eq!(fee.user_fee_sat, 600);
		assert_eq!(fee.routing_fee_sat, None);
		assert_eq!(fee.round_seq, None);

		// A client that lost the first response registers again, a block later.
		confirm(utxo.txid, 1).await;
		rpc.register_board_vtxo(register).await.unwrap();

		let status = rpc.get_vtxo_status(protos::GetVtxoStatusRequest {
			vtxo_id: vtxo.id().to_bytes().to_vec(),
			attestation: VtxoStatusAttestation::new(vtxo.id(), &key).serialize(),
		}).await.unwrap().into_inner();
		assert_eq!(status.spend_state(), protos::VtxoSpendState::Spendable);

		vtxo
	}).await;

	// The server only cosigns a funding tx whose inputs spend txs that bitcoind knows
	Box::pin(async {
		// One output of 100_000 sat, spending `inputs`. The server never
		// broadcasts the funding tx, so it needn't be signed.
		let funding_tx_spending = |inputs: &[OutPoint]| Transaction {
			version: transaction::Version::TWO,
			lock_time: absolute::LockTime::ZERO,
			input: inputs.iter().map(|p| TxIn {
				previous_output: *p,
				script_sig: ScriptBuf::new(),
				sequence: Sequence::ZERO,
				witness: Witness::new(),
			}).collect(),
			output: vec![TxOut { value: sat(100_000), script_pubkey: ScriptBuf::new() }],
		};
		let key = Keypair::new(&SECP, &mut thread_rng());
		let (_sec_nonce, nonce) = musig::nonce_pair(&key);
		let expiry = tip().await + info.vtxo_lifetime;

		// Spends a tx that bitcoind has never seen
		let unknown = Txid::from_str("0000000000000000000000000000000000000000000000000000000000000001").unwrap();
		let funding_tx = funding_tx_spending(&[OutPoint::new(unknown, 0)]);
		let utxo = OutPoint::new(funding_tx.compute_txid(), 0);
		let req = cosign_request(&key, &nonce, expiry, sat(100_000), utxo, &funding_tx);
		let err = rpc.request_board_cosign(req).await.unwrap_err();
		assert_eq!(err.code(), tonic::Code::InvalidArgument, "{err}");
		assert!(err.message().contains(&format!("unknown input tx {unknown}")), "{err}");

		// Spends a vtxo, which has no output onchain
		let funding_tx = funding_tx_spending(&[board_vtxo.id().to_point()]);
		let utxo = OutPoint::new(funding_tx.compute_txid(), 0);
		let req = cosign_request(&key, &nonce, expiry, sat(100_000), utxo, &funding_tx);
		let err = rpc.request_board_cosign(req).await.unwrap_err();
		assert_eq!(err.code(), tonic::Code::InvalidArgument, "{err}");
		assert!(err.message().contains(&format!("input is a VTXO: {}", board_vtxo.id())), "{err}");

		// Spends a tx that is still in the mempool, which the server accepts.
		let address = ctx.bitcoind().get_new_address();
		let input_txid = ctx.bitcoind().fund_addr(&address, sat(200_000)).await;
		let funding_tx = funding_tx_spending(&[OutPoint::new(input_txid, 0)]);
		let utxo = OutPoint::new(funding_tx.compute_txid(), 0);
		let req = cosign_request(&key, &nonce, expiry, sat(100_000), utxo, &funding_tx);
		let cosign = rpc.request_board_cosign(req).await.unwrap().into_inner();
		BoardCosignResponse::try_from(cosign).unwrap();
	}).await;

	// Register a board cosigned by another server
	Box::pin(async {
		// The client holds both keys, so it could sign a second spend of the board utxo.
		let other_server = Keypair::new(&SECP, &mut thread_rng());
		let expiry = tip().await + info.vtxo_lifetime;
		let (key, builder) = new_board(other_server.public_key(), expiry);
		let (_funding_tx, utxo) = fund(&builder, sat(100_000)).await;
		let builder = builder.set_funding_details(sat(100_000), sat(200), utxo).unwrap()
			.generate_user_nonces();
		let cosign = BoardBuilder::new_for_cosign(
			key.public_key(), expiry, other_server.public_key(), info.vtxo_exit_delta,
			sat(100_000), sat(200), utxo, *builder.user_pub_nonce(),
		).server_cosign(&other_server);
		let vtxo = builder.build_vtxo(&cosign, &key).unwrap();
		confirm(utxo.txid, u32::try_from(srv.config().required_board_confirmations).unwrap()).await;

		let err = rpc.register_board_vtxo(protos::BoardVtxoRequest { board_vtxo: vtxo.serialize() })
			.await.unwrap_err();
		assert_eq!(err.code(), tonic::Code::InvalidArgument, "{err}");
		assert!(err.message().contains("server pubkey"), "{err}");
	}).await;

	// Exit a board before it is registered
	Box::pin(async {
		let expiry = tip().await + info.vtxo_lifetime;
		let (key, builder) = new_board(info.server_pubkey, expiry);
		let (funding_tx, utxo) = fund(&builder, sat(100_000)).await;
		let builder = builder.set_funding_details(sat(100_000), sat(200), utxo).unwrap()
			.generate_user_nonces();
		let req = cosign_request(&key, builder.user_pub_nonce(), expiry, sat(100_000), utxo, &funding_tx);
		let cosign = rpc.request_board_cosign(req).await.unwrap().into_inner();
		let vtxo = builder.build_vtxo(&cosign.try_into().unwrap(), &key).unwrap();
		confirm(utxo.txid, u32::try_from(srv.config().required_board_confirmations).unwrap()).await;

		// The exit tx spends the board utxo. It is still in the mempool.
		let exit_tx = vtxo.transactions().next().unwrap().tx;
		ctx.broadcast_cpfp(&exit_tx).await;

		let err = rpc.register_board_vtxo(protos::BoardVtxoRequest { board_vtxo: vtxo.serialize() })
			.await.unwrap_err();
		assert_eq!(err.code(), tonic::Code::InvalidArgument, "{err}");
		assert!(err.message().contains("already spent"), "{err}");
	}).await;

	// Board with a funding tx that pays to a blocked address
	Box::pin(async {
		let expiry = tip().await + info.vtxo_lifetime;
		let (key, builder) = new_board(info.server_pubkey, expiry);
		let (funding_tx, utxo) = fund(&builder, sat(100_000)).await;
		let builder = builder.set_funding_details(sat(100_000), sat(200), utxo).unwrap()
			.generate_user_nonces();
		let req = cosign_request(&key, builder.user_pub_nonce(), expiry, sat(100_000), utxo, &funding_tx);
		let blocked_addr = block(&builder.funding_script_pubkey()).await;

		let mut blocked = srv.subscribe_log::<BoardAttemptBlockedAddress>();
		let err = rpc.request_board_cosign(req).await.unwrap_err();
		assert_eq!(err.code(), tonic::Code::InvalidArgument, "{err}");
		assert!(err.message().contains("blocked"), "{err}");
		// No vtxo exists yet, so the log has no vtxo id.
		let log = blocked.recv().await.unwrap();
		assert_eq!(log.address.assume_checked(), blocked_addr);
		assert_eq!(log.vtxo, None);
		assert_eq!(log.amount, sat(100_000));
	}).await;

	// Board with a funding tx that spends from a blocked address
	Box::pin(async {
		let source = ctx.bitcoind().get_new_address();

		// A board cosigned before its source address is blocked
		let expiry = tip().await + info.vtxo_lifetime;
		let (key, builder) = new_board(info.server_pubkey, expiry);
		let (funding_tx, utxo) = fund_from(&source, &builder).await;
		let builder = builder.set_funding_details(sat(100_000), sat(200), utxo).unwrap()
			.generate_user_nonces();
		let req = cosign_request(&key, builder.user_pub_nonce(), expiry, sat(100_000), utxo, &funding_tx);
		let cosign = rpc.request_board_cosign(req).await.unwrap().into_inner();
		let vtxo = builder.build_vtxo(&cosign.try_into().unwrap(), &key).unwrap();
		confirm(utxo.txid, u32::try_from(srv.config().required_board_confirmations).unwrap()).await;

		block(&source.script_pubkey()).await;
		let mut blocked = srv.subscribe_log::<BoardAttemptBlockedAddress>();

		// The board is refused at registration
		let err = rpc.register_board_vtxo(protos::BoardVtxoRequest { board_vtxo: vtxo.serialize() })
			.await.unwrap_err();
		assert_eq!(err.code(), tonic::Code::InvalidArgument, "{err}");
		assert!(err.message().contains("blocked"), "{err}");
		let log = blocked.recv().await.unwrap();
		assert_eq!(log.address.assume_checked(), source);
		assert_eq!(log.vtxo, Some(vtxo.id()));

		// A new board from the blocked address is refused at cosign
		let (key, builder) = new_board(info.server_pubkey, expiry);
		let (funding_tx, utxo) = fund_from(&source, &builder).await;
		let builder = builder.set_funding_details(sat(100_000), sat(200), utxo).unwrap()
			.generate_user_nonces();
		let req = cosign_request(&key, builder.user_pub_nonce(), expiry, sat(100_000), utxo, &funding_tx);
		let err = rpc.request_board_cosign(req).await.unwrap_err();
		assert_eq!(err.code(), tonic::Code::InvalidArgument, "{err}");
		assert!(err.message().contains("blocked"), "{err}");
		let log = blocked.recv().await.unwrap();
		assert_eq!(log.address.assume_checked(), source);
		assert_eq!(log.vtxo, None);
		assert_eq!(log.amount, sat(100_000));
	}).await;

	// Cosign a board utxo again after the server changed its fee
	Box::pin(async {
		let expiry = tip().await + info.vtxo_lifetime;
		let (key, builder) = new_board(info.server_pubkey, expiry);
		let (funding_tx, utxo) = fund(&builder, sat(100_000)).await;
		// Cosigns the board utxo with `fee` taken out.
		let cosign = async |fee: Amount| {
			let builder = BoardBuilder::new(key.public_key(), expiry, info.server_pubkey, info.vtxo_exit_delta).unwrap()
				.set_funding_details(sat(100_000), fee, utxo).unwrap()
				.generate_user_nonces();
			let req = cosign_request(&key, builder.user_pub_nonce(), expiry, sat(100_000), utxo, &funding_tx);
			let cosign = srv.get_public_rpc().await.request_board_cosign(req).await?
				.into_inner();
			Ok::<_, tonic::Status>(builder.build_vtxo(&cosign.try_into().unwrap(), &key).unwrap())
		};
		let first = cosign(sat(200)).await.unwrap();

		// The fee is now 1_000 sat + 0.1%. Boards also need at least 30_000 sat.
		srv.stop().await.unwrap();
		srv.config_mut().fees.board.base_fee = sat(1_000);
		srv.config_mut().min_board_amount = sat(30_000);
		srv.start().await.unwrap();
		// A restart reserves new ports, so connect again.
		rpc = srv.get_public_rpc().await;

		// Below min_board_amount
		let key = Keypair::new(&SECP, &mut thread_rng());
		let (_sec_nonce, nonce) = musig::nonce_pair(&key);
		let req = cosign_request(&key, &nonce, expiry, sat(29_999), utxo, &funding_tx);
		let err = rpc.request_board_cosign(req).await.unwrap_err();
		assert_eq!(err.code(), tonic::Code::InvalidArgument, "{err}");
		assert!(err.message().contains("board amount must be at least 0.00030000 BTC"), "{err}");

		// The new fee changes the exit tx, but the server signs one exit tx per board utxo
		let err = cosign(sat(1_100)).await.unwrap_err();
		assert_eq!(err.code(), tonic::Code::InvalidArgument, "{err}");
		assert!(err.message().contains("already cosigned"), "{err}");

		// Servers before this check could sign two exit txs. Deleting the bindings
		// recreates that, and only one of the two exit txs registers.
		let db = Db::connect(&srv.config().postgres).await.unwrap();
		let unbind = async || {
			db.write(async |t| Ok(t.execute("DELETE FROM board_exit", &[]).await?)).await.unwrap();
		};
		unbind().await;
		let second = cosign(sat(1_100)).await.unwrap();
		assert_ne!(first.id(), second.id());
		unbind().await;
		confirm(utxo.txid, u32::try_from(srv.config().required_board_confirmations).unwrap()).await;
		rpc.register_board_vtxo(protos::BoardVtxoRequest { board_vtxo: first.serialize() })
			.await.unwrap();
		let err = rpc.register_board_vtxo(protos::BoardVtxoRequest { board_vtxo: second.serialize() })
			.await.unwrap_err();
		assert_eq!(err.code(), tonic::Code::InvalidArgument, "{err}");
		assert!(err.message().contains("already registered"), "{err}");
	}).await;

	// Register a board whose funding tx pays to an address blocked after the cosign
	Box::pin(async {
		// The fee is 1_000 sat + 0.1% since the restart above.
		let expiry = tip().await + info.vtxo_lifetime;
		let (key, builder) = new_board(info.server_pubkey, expiry);
		let (funding_tx, utxo) = fund(&builder, sat(100_000)).await;
		let builder = builder.set_funding_details(sat(100_000), sat(1_100), utxo).unwrap()
			.generate_user_nonces();
		let req = cosign_request(&key, builder.user_pub_nonce(), expiry, sat(100_000), utxo, &funding_tx);
		let cosign = rpc.request_board_cosign(req).await.unwrap().into_inner();
		let vtxo = builder.build_vtxo(&cosign.try_into().unwrap(), &key).unwrap();

		// A board of another key on the same utxo, which pays to another script
		let (decoy_key, decoy_builder) = new_board(info.server_pubkey, expiry);
		let decoy_builder = decoy_builder.set_funding_details(sat(100_000), sat(1_100), utxo).unwrap()
			.generate_user_nonces();
		let req = cosign_request(&decoy_key, decoy_builder.user_pub_nonce(), expiry, sat(100_000), utxo, &funding_tx);
		let cosign = rpc.request_board_cosign(req).await.unwrap().into_inner();
		let decoy = decoy_builder.build_vtxo(&cosign.try_into().unwrap(), &decoy_key).unwrap();
		confirm(utxo.txid, u32::try_from(srv.config().required_board_confirmations).unwrap()).await;

		block(&funding_tx.output[utxo.vout as usize].script_pubkey).await;

		// The decoy is refused before the blocklist looks up the funding tx's inputs
		let err = rpc.register_board_vtxo(protos::BoardVtxoRequest { board_vtxo: decoy.serialize() })
			.await.unwrap_err();
		assert_eq!(err.code(), tonic::Code::InvalidArgument, "{err}");
		assert!(err.message().contains("invalid vtxo"), "{err}");

		let mut blocked = srv.subscribe_log::<BoardAttemptBlockedAddress>();
		let err = rpc.register_board_vtxo(protos::BoardVtxoRequest { board_vtxo: vtxo.serialize() })
			.await.unwrap_err();
		assert_eq!(err.code(), tonic::Code::InvalidArgument, "{err}");
		assert!(err.message().contains("blocked"), "{err}");
		// The vtxo exists now, so the log has its id.
		let log = blocked.recv().await.unwrap();
		assert_eq!(log.vtxo, Some(vtxo.id()));
	}).await;

	// A max_board_amount of zero disables boards entirely
	Box::pin(async {
		// A board cosigned before boards are disabled.
		// The fee is 1_000 sat + 0.1% since the restart above.
		let expiry = tip().await + info.vtxo_lifetime;
		let (key, builder) = new_board(info.server_pubkey, expiry);
		let (funding_tx, utxo) = fund(&builder, sat(100_000)).await;
		let builder = builder.set_funding_details(sat(100_000), sat(1_100), utxo).unwrap()
			.generate_user_nonces();
		let req = cosign_request(&key, builder.user_pub_nonce(), expiry, sat(100_000), utxo, &funding_tx);
		let cosign = rpc.request_board_cosign(req.clone()).await.unwrap().into_inner();
		let vtxo = builder.build_vtxo(&cosign.try_into().unwrap(), &key).unwrap();
		confirm(utxo.txid, u32::try_from(srv.config().required_board_confirmations).unwrap()).await;

		srv.stop().await.unwrap();
		srv.config_mut().max_board_amount = Some(Amount::ZERO);
		srv.start().await.unwrap();
		rpc = srv.get_public_rpc().await;

		// The cosign is refused
		let err = rpc.request_board_cosign(req).await.unwrap_err();
		assert_eq!(err.code(), tonic::Code::InvalidArgument, "{err}");
		assert!(err.message().contains("board is temporarily disabled"), "{err}");

		// The registration of the board cosigned before is refused
		let err = rpc.register_board_vtxo(protos::BoardVtxoRequest { board_vtxo: vtxo.serialize() })
			.await.unwrap_err();
		assert_eq!(err.code(), tonic::Code::InvalidArgument, "{err}");
		assert!(err.message().contains("board is temporarily disabled"), "{err}");
	}).await;
}
