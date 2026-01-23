
use std::iter;
use std::collections::HashMap;
use std::str::FromStr;

use bitcoin::absolute::LockTime;
use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::hex::{DisplayHex, FromHex};
use bitcoin::secp256k1::Keypair;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

use crate::{musig, Vtxo, VtxoPolicy, VtxoRequest, SECP};
use crate::arkoor::ArkoorDestination;
use crate::arkoor::package::ArkoorPackageBuilder;
use crate::board::BoardBuilder;
use crate::encode::ProtocolEncoding;
use crate::lightning::PaymentHash;
use crate::tree::signed::{UnlockHash, UnlockPreimage, VtxoLeafSpec, VtxoTreeSpec};
use crate::test_util::encoding_roundtrip;
use crate::vtxo::{PubkeyVtxoPolicy, ServerHtlcSendVtxoPolicy};

#[allow(unused)]
#[macro_export]
macro_rules! assert_eq_vtxos {
	($v1:expr, $v2:expr) => {
		let v1 = &$v1;
		let v2 = &$v2;
		assert_eq!(
			v1.serialize().as_hex().to_string(),
			v2.serialize().as_hex().to_string(),
			"vtxo {} != {}", v1.id(), v2.id(),
		);
	};
}

#[derive(Debug, PartialEq, Eq)]
pub struct VtxoTestVectors {
	pub server_key: Keypair,

	pub anchor_tx: Transaction,
	pub board_vtxo: Vtxo,

	pub arkoor_htlc_out_vtxo: Vtxo,
	pub arkoor2_vtxo: Vtxo,

	pub round_tx: Transaction,
	pub round1_vtxo: Vtxo,
	pub round2_vtxo: Vtxo,

	pub arkoor3_user_key: Keypair,
	pub arkoor3_vtxo: Vtxo,
}

pub fn generate_vtxo_vectors() -> VtxoTestVectors {
	let expiry_height = 101_010;
	let exit_delta = 2016;
	let server_key = Keypair::from_str("916da686cedaee9a9bfb731b77439f2a3f1df8664e16488fba46b8d2bfe15e92").unwrap();
	let board_user_key = Keypair::from_str("fab9e598081a3e74b2233d470c4ad87bcc285b6912ed929568e62ac0e9409879").unwrap();
	let amount = Amount::from_sat(10_000);
	let builder = BoardBuilder::new(
		board_user_key.public_key(),
		expiry_height,
		server_key.public_key(),
		exit_delta,
	);
	let anchor_tx = Transaction {
		version: Version::TWO,
		lock_time: LockTime::ZERO,
		input: vec![TxIn {
			previous_output: OutPoint::null(),
			script_sig: ScriptBuf::new(),
			sequence: Sequence::ZERO,
			witness: Witness::new(),
		}],
		output: vec![TxOut {
			value: Amount::from_sat(10_000),
			script_pubkey: builder.funding_script_pubkey(),
		}],
	};
	println!("chain anchor tx: {}", serialize_hex(&anchor_tx));
	let anchor_point = OutPoint::new(anchor_tx.compute_txid(), 0);
	let builder = builder.set_funding_details(amount, anchor_point)
		.generate_user_nonces();

	let board_cosign = {
		BoardBuilder::new_for_cosign(
			builder.user_pubkey,
			builder.expiry_height,
			builder.server_pubkey,
			builder.exit_delta,
			amount,
			anchor_point,
			*builder.user_pub_nonce(),
		).server_cosign(&server_key)
	};

	assert!(builder.verify_cosign_response(&board_cosign));
	let board_vtxo = builder.build_vtxo(&board_cosign, &board_user_key).unwrap();
	encoding_roundtrip(&board_vtxo);
	println!("board vtxo: {}", board_vtxo.serialize().as_hex());

	// arkoor1: htlc send

	let arkoor_htlc_out_user_key = Keypair::from_str("33b6f3ede430a1a53229f55da7117242d8392cbfc64a57249ba70731dba71408").unwrap();
	let payment_hash = PaymentHash::from(sha256::Hash::hash("arkoor1".as_bytes()).to_byte_array());
	let arkoor1_dest1 = ArkoorDestination {
		total_amount: Amount::from_sat(9000),
		policy: VtxoPolicy::ServerHtlcSend(ServerHtlcSendVtxoPolicy {
			user_pubkey: arkoor_htlc_out_user_key.public_key(),
			payment_hash,
			htlc_expiry: expiry_height - 1000,
		}),
	};
	let arkoor1_dest2 = ArkoorDestination {
		total_amount: Amount::from_sat(1000),
		policy: VtxoPolicy::new_pubkey("0229b7de0ce4d573192d002a6f9fd1109e00f7bae52bf10780d6f6e73e12a8390f".parse().unwrap()),
	};
	let builder = ArkoorPackageBuilder::new_with_checkpoints(
		[board_vtxo.clone()], vec![arkoor1_dest1, arkoor1_dest2],
	).unwrap().generate_user_nonces(&[board_user_key]).unwrap();
	let cosign = ArkoorPackageBuilder::from_cosign_request(
		builder.cosign_request(),
	).unwrap().server_cosign(&server_key).unwrap().cosign_response();
	let [arkoor_htlc_out_vtxo, change] = builder.user_cosign(&[board_user_key], cosign).unwrap()
		.build_signed_vtxos().try_into().unwrap();
	encoding_roundtrip(&arkoor_htlc_out_vtxo);
	encoding_roundtrip(&change);
	println!("arkoor1_vtxo: {}", arkoor_htlc_out_vtxo.serialize().as_hex());

	// arkoor2: regular pubkey

	let arkoor2_user_key = Keypair::from_str("fcc43a4f03356092a945ca1d7218503156bed3f94c2fa224578ce5b158fbf5a6").unwrap();
	let arkoor2_dest1 = ArkoorDestination {
		total_amount: Amount::from_sat(8000),
		policy: VtxoPolicy::new_pubkey(arkoor2_user_key.public_key()),
	};
	let arkoor2_dest2 = ArkoorDestination {
		total_amount: Amount::from_sat(1000),
		policy: VtxoPolicy::new_pubkey("037039dc4f4b16e78059d2d56eb98d181cb1bdff2675694d39d92c4a2ea08ced88".parse().unwrap()),
	};
	let builder = ArkoorPackageBuilder::new_with_checkpoints(
		[arkoor_htlc_out_vtxo.clone()], vec![arkoor2_dest1, arkoor2_dest2],
	).unwrap().generate_user_nonces(&[arkoor_htlc_out_user_key]).unwrap();
	let cosign = ArkoorPackageBuilder::from_cosign_request(
		builder.cosign_request(),
	).unwrap().server_cosign(&server_key).unwrap().cosign_response();
	let [arkoor2_vtxo, change] = builder.user_cosign(&[arkoor_htlc_out_user_key], cosign).unwrap()
		.build_signed_vtxos().try_into().unwrap();
	encoding_roundtrip(&arkoor2_vtxo);
	encoding_roundtrip(&change);
	println!("arkoor2_vtxo: {}", arkoor2_vtxo.serialize().as_hex());

	// round 1

	//TODO(stevenroose) rename to round htlc in
	let round1_user_key = Keypair::from_str("0a832e9574070c94b5b078600a18639321c880c830c5ba2f2a96850c7dcc4725").unwrap();
	let round1_cosign_key = Keypair::from_str("e14bfc3199842c76816eec1d93c9da00b850c4ed19e414e246d07e845e465a2b").unwrap();
	let round1_unlock_preimage = UnlockPreimage::from_hex("c05bc2f82c8c64e470cd4d87aca42989b46879ca32320cd035db124bb78c4e74").unwrap();
	let round1_unlock_hash = UnlockHash::hash(&round1_unlock_preimage);
	println!("round1_cosign_key: {}", round1_cosign_key.public_key());
	let round1_req = VtxoLeafSpec {
		vtxo: VtxoRequest {
			amount: Amount::from_sat(10_000),
			policy: VtxoPolicy::new_pubkey(round1_user_key.public_key()),
		},
		cosign_pubkey: Some(round1_cosign_key.public_key()),
		unlock_hash: round1_unlock_hash,
	};
	let round1_nonces = iter::repeat_with(|| musig::nonce_pair(&round1_cosign_key)).take(5).collect::<Vec<_>>();

	let round2_user_key = Keypair::from_str("c0b645b01cac427717a18b30c7c9238dee2b3885f659930144fbe05061ad6166").unwrap();
	let round2_cosign_key = Keypair::from_str("628789cd7b7e02766d184ecfecc433798c9640349e41822df7996c66a56fc633").unwrap();
	let round2_unlock_preimage = UnlockPreimage::from_hex("61050792ef121826fda248a789c8ba75b955844c65acd2c6361950bdd31dae7d").unwrap();
	let round2_unlock_hash = UnlockHash::hash(&round2_unlock_preimage);
	println!("round2_cosign_key: {}", round2_cosign_key.public_key());
	let round2_payment_hash = PaymentHash::from(sha256::Hash::hash("round2".as_bytes()).to_byte_array());
	let round2_req = VtxoLeafSpec {
		vtxo: VtxoRequest {
			amount: Amount::from_sat(10_000),
			policy: VtxoPolicy::new_server_htlc_recv(
				round2_user_key.public_key(),
				round2_payment_hash,
				expiry_height - 2000,
				40,
			),
		},
		cosign_pubkey: Some(round2_cosign_key.public_key()),
		unlock_hash: round2_unlock_hash,
	};
	let round2_nonces = iter::repeat_with(|| musig::nonce_pair(&round2_cosign_key)).take(5).collect::<Vec<_>>();

	let others = [
		"93b376f64ada74f0fbf940be86f888459ac94655dc6a7805cc790b3c95a2a612",
		"00add86ff531ef53f877780622f0b376669ec6ad7e090131820ff7007e79f529",
		"775b836f2acf53de4ff9beeba2a17d5475e9b027d82fece72033ef06b954c7cd",
		"395c2c210481990a5d12d33dca37995e235a34b717c89647a33907c62e32dc09",
		"8f02f2a7aa1746bbcc92bba607b7166b6a77e9d0efd9d09dae7c2dc3addbdef1",
	];
	let mut other_reqs = Vec::new();
	let mut other_nonces = Vec::new();
	for k in others {
		let user_key = Keypair::from_str(k).unwrap();
		let cosign_key = Keypair::from_seckey_slice(&SECP, &sha256::Hash::hash(k.as_bytes())[..]).unwrap();
		other_reqs.push(VtxoLeafSpec {
			vtxo: VtxoRequest {
				amount: Amount::from_sat(5_000),
				policy: VtxoPolicy::new_pubkey(user_key.public_key()),
			},
			cosign_pubkey: Some(cosign_key.public_key()),
			unlock_hash: sha256::Hash::hash(k.as_bytes()),
		});
		other_nonces.push(iter::repeat_with(|| musig::nonce_pair(&cosign_key)).take(5).collect::<Vec<_>>());
	}

	let server_cosign_key = Keypair::from_str("4371a4a7989b89ebe1b2582db4cd658cb95070977e6f10601ddc1e9b53edee79").unwrap();
	let spec = VtxoTreeSpec::new(
		[&round1_req, &round2_req].into_iter().chain(other_reqs.iter()).cloned().collect(),
		server_key.public_key(),
		expiry_height,
		exit_delta,
		vec![server_cosign_key.public_key()],
	);
	let round_tx = Transaction {
		version: Version::TWO,
		lock_time: LockTime::ZERO,
		input: vec![TxIn {
			previous_output: OutPoint::null(),
			script_sig: ScriptBuf::new(),
			sequence: Sequence::ZERO,
			witness: Witness::new(),
		}],
		output: vec![TxOut {
			value: Amount::from_sat(45_000),
			script_pubkey: spec.funding_tx_script_pubkey(),
		}],
	};
	println!("round tx: {}", serialize_hex(&round_tx));
	let all_nonces = {
		let mut map = HashMap::new();
		map.insert(round1_cosign_key.public_key(), round1_nonces.iter().map(|n| n.1).collect::<Vec<_>>());
		map.insert(round2_cosign_key.public_key(), round2_nonces.iter().map(|n| n.1).collect::<Vec<_>>());
		for (req, nonces) in other_reqs.iter().zip(other_nonces.iter()) {
			map.insert(req.cosign_pubkey.unwrap(), nonces.iter().map(|n| n.1).collect::<Vec<_>>());
		}
		map
	};
	let (server_cosign_sec_nonces, server_cosign_pub_nonces) = iter::repeat_with(|| {
		musig::nonce_pair(&server_cosign_key)
	}).take(spec.nb_internal_nodes()).unzip::<_, _, Vec<_>, Vec<_>>();
	let cosign_agg_nonces = spec.calculate_cosign_agg_nonces(&all_nonces, &[&server_cosign_pub_nonces]).unwrap();
	let root_point = OutPoint::new(round_tx.compute_txid(), 0);
	let tree = spec.into_unsigned_tree(root_point);
	let part_sigs = {
		let mut map = HashMap::new();
		map.insert(round1_cosign_key.public_key(), {
			let secs = round1_nonces.into_iter().map(|(s, _)| s).collect();
			let r = tree.cosign_branch(&cosign_agg_nonces, 0, &round1_cosign_key, secs).unwrap();
			r
		});
		map.insert(round2_cosign_key.public_key(), {
			let secs = round2_nonces.into_iter().map(|(s, _)| s).collect();
			tree.cosign_branch(&cosign_agg_nonces, 1, &round2_cosign_key, secs).unwrap()
		});
		for (i, (req, nonces)) in other_reqs.iter().zip(other_nonces.into_iter()).enumerate() {
			let cosign_key = Keypair::from_seckey_slice(
				&SECP, &sha256::Hash::hash(others[i].as_bytes())[..],
			).unwrap();
			map.insert(req.cosign_pubkey.unwrap(), {
				let secs = nonces.into_iter().map(|(s, _)| s).collect();
				tree.cosign_branch(&cosign_agg_nonces, 2 + i, &cosign_key, secs).unwrap()
			});
		}
		map
	};
	let server_cosign_sigs = tree.cosign_tree(
		&cosign_agg_nonces, &server_cosign_key, server_cosign_sec_nonces,
	);
	let cosign_sigs = tree.combine_partial_signatures(&cosign_agg_nonces, &part_sigs, &[&server_cosign_sigs]).unwrap();
	if let Err(pk) = tree.verify_cosign_sigs(&cosign_sigs) {
		panic!("invalid cosign sig for pk: {}", pk);
	}
	let signed = tree.into_signed_tree(cosign_sigs).into_cached_tree();
	// we don't need forfeits
	let mut vtxo_iter = signed.all_vtxos();
	let round1_vtxo = {
		let mut ret = vtxo_iter.next().unwrap();
		ret.finalize_hark_leaf(&round1_user_key, &server_key, &round_tx, round1_unlock_preimage);
		ret
	};
	encoding_roundtrip(&round1_vtxo);
	println!("round1_vtxo: {}", round1_vtxo.serialize().as_hex());
	let round2_vtxo = {
		let mut ret = vtxo_iter.next().unwrap();
		ret.finalize_hark_leaf(&round2_user_key, &server_key, &round_tx, round2_unlock_preimage);
		ret
	};
	encoding_roundtrip(&round2_vtxo);
	println!("round2_vtxo: {}", round2_vtxo.serialize().as_hex());

	// arkoor3: off from round2's htlc

	let arkoor3_user_key = Keypair::from_str("ad12595bdbdab56cb61d1f60ccc46ff96b11c5d6fe06ae7ba03d3a5f4347440f").unwrap();
	let arkoor3_dest = ArkoorDestination {
		total_amount: Amount::from_sat(10_000),
		policy: VtxoPolicy::Pubkey(PubkeyVtxoPolicy { user_pubkey: arkoor3_user_key.public_key() }),
	};
	let builder = ArkoorPackageBuilder::new_with_checkpoints(
		[round2_vtxo.clone()], vec![arkoor3_dest],
	).unwrap().generate_user_nonces(&[round2_user_key]).unwrap();
	let cosign = ArkoorPackageBuilder::from_cosign_request(
		builder.cosign_request(),
	).unwrap().server_cosign(&server_key).unwrap().cosign_response();
	let [arkoor3_vtxo] = builder.user_cosign(&[round2_user_key], cosign).unwrap()
		.build_signed_vtxos().try_into().unwrap();
	encoding_roundtrip(&arkoor3_vtxo);
	println!("arkoor3_vtxo: {}", arkoor3_vtxo.serialize().as_hex());

	VtxoTestVectors {
		server_key,
		anchor_tx,
		board_vtxo,
		arkoor_htlc_out_vtxo,
		arkoor2_vtxo,
		round_tx,
		round1_vtxo,
		round2_vtxo,
		arkoor3_user_key,
		arkoor3_vtxo,
	}
}

lazy_static! {
	/// A set of deterministically generated and fully correct VTXOs.
	pub static ref VTXO_VECTORS: VtxoTestVectors = VtxoTestVectors {
		server_key: Keypair::from_str("916da686cedaee9a9bfb731b77439f2a3f1df8664e16488fba46b8d2bfe15e92").unwrap(),
		anchor_tx: deserialize_hex("02000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0000000000011027000000000000225120652675904a84ea02e24b57b3d547203d2ce71526113d35bf4d02e0b4efbe9a2d00000000").unwrap(),
		board_vtxo: ProtocolEncoding::deserialize_hex("01001027000000000000928a01000365a81233741893bbe2461b8d479dadc5880594fe6f7479180d5843820af72b62e007ed4d23932a2625a78fe5c75bded751da3a99e23a297a527c01bd7bc8372128f200000000010102030a752219f1b94bbdf8994a0a980cdda08c2ad094cb29dd834878db6dee1612ee0365a81233741893bbe2461b8d479dadc5880594fe6f7479180d5843820af72b62655d61f465693e1fbf39814e9cb1d57d5eabc49548ed042626cc39c4d5fe5c1836c8c2fb634bceab363212ed4c6a8e78c9ff33884587830ffa2a1cbd84c95e77010000030a752219f1b94bbdf8994a0a980cdda08c2ad094cb29dd834878db6dee1612ee4c99b744ad009b7070f330794bf003fa8e5cd46ea1a6eb854aaf469385e3080000000000").unwrap(),
		arkoor_htlc_out_vtxo: ProtocolEncoding::deserialize_hex("01002823000000000000928a01000365a81233741893bbe2461b8d479dadc5880594fe6f7479180d5843820af72b62e007ed4d23932a2625a78fe5c75bded751da3a99e23a297a527c01bd7bc8372128f200000000030102030a752219f1b94bbdf8994a0a980cdda08c2ad094cb29dd834878db6dee1612ee0365a81233741893bbe2461b8d479dadc5880594fe6f7479180d5843820af72b62655d61f465693e1fbf39814e9cb1d57d5eabc49548ed042626cc39c4d5fe5c1836c8c2fb634bceab363212ed4c6a8e78c9ff33884587830ffa2a1cbd84c95e7701000201030a752219f1b94bbdf8994a0a980cdda08c2ad094cb29dd834878db6dee1612ee78b9640f859155786c4923b1d634d20b02663f1c4d061c4411f15e386951a63f6df2b91823cc3d3a0e18ac32104a9a649d3842245932f87e77fa4402a4c91f14b7b629421b17be09173f277f3ae4f413b294a825188d89834a1e23c9139388240200e803000000000000225120652675904a84ea02e24b57b3d547203d2ce71526113d35bf4d02e0b4efbe9a2d0201030a752219f1b94bbdf8994a0a980cdda08c2ad094cb29dd834878db6dee1612eea77a828ce5ccaca57a4b78f16499219334c6ee95c9b990ee15918aeb9159300565f82f1a66bc0b197516209817f9b89b6b2d54a640a667dc07021d100ec07b4c684c03fb4cb2442f3cba4ea2b17b460001dc8299e832880685d22c9ef24ce64801000103eb4570ae385202d4a48f06bdb14126910b90c07f8e42d7dc5e28a860c085e73712358912c950a9a7d04bb9011ee9f6a16b6127a5aab7415803d48c0225f620f5aa8601006b46ceafff6c10e1c1d07fa308e79cfdac35e952c1e2ccf3f8c9797c776db17200000000").unwrap(),
		arkoor2_vtxo: ProtocolEncoding::deserialize_hex("0100401f000000000000928a01000365a81233741893bbe2461b8d479dadc5880594fe6f7479180d5843820af72b62e007ed4d23932a2625a78fe5c75bded751da3a99e23a297a527c01bd7bc8372128f200000000050102030a752219f1b94bbdf8994a0a980cdda08c2ad094cb29dd834878db6dee1612ee0365a81233741893bbe2461b8d479dadc5880594fe6f7479180d5843820af72b62655d61f465693e1fbf39814e9cb1d57d5eabc49548ed042626cc39c4d5fe5c1836c8c2fb634bceab363212ed4c6a8e78c9ff33884587830ffa2a1cbd84c95e7701000201030a752219f1b94bbdf8994a0a980cdda08c2ad094cb29dd834878db6dee1612ee78b9640f859155786c4923b1d634d20b02663f1c4d061c4411f15e386951a63f6df2b91823cc3d3a0e18ac32104a9a649d3842245932f87e77fa4402a4c91f14b7b629421b17be09173f277f3ae4f413b294a825188d89834a1e23c9139388240200e803000000000000225120652675904a84ea02e24b57b3d547203d2ce71526113d35bf4d02e0b4efbe9a2d0201030a752219f1b94bbdf8994a0a980cdda08c2ad094cb29dd834878db6dee1612eea77a828ce5ccaca57a4b78f16499219334c6ee95c9b990ee15918aeb9159300565f82f1a66bc0b197516209817f9b89b6b2d54a640a667dc07021d100ec07b4c684c03fb4cb2442f3cba4ea2b17b460001dc8299e832880685d22c9ef24ce6480100020103eb4570ae385202d4a48f06bdb14126910b90c07f8e42d7dc5e28a860c085e737474fa0103bd24e02383f053a708ed3b3cb9818aab2410d1828fa3070836fa5e71b2e02e0edbb3c5382a80ad069686debf9ad0e27df88eaaa0a08417271c1fe67a89a3ce8cf1fe5954c867e29a3c9e50892eb0a60bcbe25c4505ff3709554322c0200e80300000000000022512045827da6714a3cadf6646b36f4e18841a8572d7c6f849e8376058be8381941c8020103eb4570ae385202d4a48f06bdb14126910b90c07f8e42d7dc5e28a860c085e73771985112b67c902fbaaacfc19801ee5833608e8cb73a84c20dfc541b298dc9ab5f8ce376bad23d53354c8370d3f9e7e7d1925547c5ef96011c36d5d075644a3af909ef83ee3e16a2c567b2747e56843b526cf9e9690712b8b77933c8b8bb8f490100000265cca13271cafd0b90c440e722a1937b7c4faf4ccd7dee0548d152c24ce4b2a8dca043938fa10d4ea2d54ab3743f9e092b9f671aa30161bcbd3942b46b1b195700000000").unwrap(),
		round_tx: deserialize_hex("02000000010000000000000000000000000000000000000000000000000000000000000000ffffffff000000000001c8af000000000000225120649657f65947abfd83ff629ad8a851c795f419ed4d52a2748d3f868cc3e6c94d00000000").unwrap(),
		round1_vtxo: ProtocolEncoding::deserialize_hex("01001027000000000000928a01000365a81233741893bbe2461b8d479dadc5880594fe6f7479180d5843820af72b62e007a3c23c49874159964c52b95021596d5a22e8f8b6bc7c16aa8303c24498d3d5ab00000000030108039e8a040d9c1fba5a7b0db8485d8f167f8d2590afd8595f9eb9ba7a769347ba2602bd0ad185b18089d37d20dd784b99003914faadcc59f37bbf3273a3b5cd22ed5002568a3a6d25000fc942f0443dc76be4ef688e8c8dc055591de1f2cc1c847b1ed3036e64c16a01e3d18908a15b55251a5db74ff2c1142c02abd048222893b2a18a16024ac23c8d3f6e0b1116e34f68ee7c9e4c19eba30213e8fae0925d70faf8d1ecc403932b1b0224e375471c938ea84bd17df7d8295941b2db68a6623610dd959b2eb303d215f5e88aefa7a2a9794771878f3d6caf20e884c1e0ce923cfa9dea261bb4e2024482039ebf3624525061f88aa01d4a02b3f2224eee8b4060ae0cbf036b242743d272c99b53de1036c5d3f381a6d873a759707ffc98414634943e8568ff9ddf3b57e658e0a5e0ad82daf82e783c1863aff6bccded8569199c1213e8c51407c0f6040388130000000000002251205acb7b65f8da14622a055640893e952e20f68e051087b85be4d56e50cdafd4318813000000000000225120973b9be7e6ee51f8851347130113e4001ab1d01252dd1d09713a6c900cb327f2881300000000000022512052cc228fe0f4951032fbaeb45ed8b73163cedb897412407e5b431d740040a9510105036e64c16a01e3d18908a15b55251a5db74ff2c1142c02abd048222893b2a18a16024ac23c8d3f6e0b1116e34f68ee7c9e4c19eba30213e8fae0925d70faf8d1ecc403932b1b0224e375471c938ea84bd17df7d8295941b2db68a6623610dd959b2eb303d215f5e88aefa7a2a9794771878f3d6caf20e884c1e0ce923cfa9dea261bb4e2024482039ebf3624525061f88aa01d4a02b3f2224eee8b4060ae0cbf036b242743b707706c721f8b9172188c3a9fa2709a478d40c9a89537405a4ae21df94e90d8ec24d0caa098db3c31d3d25d5414a5febf0e039da137440fa9dd932d759d364604001027000000000000225120e9d56cdf22598ce6c05950b3580e194a19e53f8b887fc6c4111ca2a82a0608a88813000000000000225120c3731a9dc38c67dfa2dd206ee346d6225f1f37b97d77d518c59b9c9a291762288813000000000000225120a4ad17a5f329a164977981f1b7638c7a70b0dd1bed29a85637aed2952dd2e38c030374a3ec37cc4ccd29717388e6dc24f2aa366632f1a36a49e73cd7671b23179298dda3af54a441d56f83e4a3924efe431b358b5c7ef8f4d92b7554706b5e3d73994ef01aa880c8d6da73fad0600715a266dd67797e2f2034f331f251e9040bbd1c00c05bc2f82c8c64e470cd4d87aca42989b46879ca32320cd035db124bb78c4e740100000374a3ec37cc4ccd29717388e6dc24f2aa366632f1a36a49e73cd7671b2317929862d6c4b8e408915af8279d4f14431f517a0c9ecc46fae2e8b0a5f72cfcf506c800000000").unwrap(),
		round2_vtxo: ProtocolEncoding::deserialize_hex("01001027000000000000928a01000365a81233741893bbe2461b8d479dadc5880594fe6f7479180d5843820af72b62e007a3c23c49874159964c52b95021596d5a22e8f8b6bc7c16aa8303c24498d3d5ab00000000030108039e8a040d9c1fba5a7b0db8485d8f167f8d2590afd8595f9eb9ba7a769347ba2602bd0ad185b18089d37d20dd784b99003914faadcc59f37bbf3273a3b5cd22ed5002568a3a6d25000fc942f0443dc76be4ef688e8c8dc055591de1f2cc1c847b1ed3036e64c16a01e3d18908a15b55251a5db74ff2c1142c02abd048222893b2a18a16024ac23c8d3f6e0b1116e34f68ee7c9e4c19eba30213e8fae0925d70faf8d1ecc403932b1b0224e375471c938ea84bd17df7d8295941b2db68a6623610dd959b2eb303d215f5e88aefa7a2a9794771878f3d6caf20e884c1e0ce923cfa9dea261bb4e2024482039ebf3624525061f88aa01d4a02b3f2224eee8b4060ae0cbf036b242743d272c99b53de1036c5d3f381a6d873a759707ffc98414634943e8568ff9ddf3b57e658e0a5e0ad82daf82e783c1863aff6bccded8569199c1213e8c51407c0f6040388130000000000002251205acb7b65f8da14622a055640893e952e20f68e051087b85be4d56e50cdafd4318813000000000000225120973b9be7e6ee51f8851347130113e4001ab1d01252dd1d09713a6c900cb327f2881300000000000022512052cc228fe0f4951032fbaeb45ed8b73163cedb897412407e5b431d740040a9510105036e64c16a01e3d18908a15b55251a5db74ff2c1142c02abd048222893b2a18a16024ac23c8d3f6e0b1116e34f68ee7c9e4c19eba30213e8fae0925d70faf8d1ecc403932b1b0224e375471c938ea84bd17df7d8295941b2db68a6623610dd959b2eb303d215f5e88aefa7a2a9794771878f3d6caf20e884c1e0ce923cfa9dea261bb4e2024482039ebf3624525061f88aa01d4a02b3f2224eee8b4060ae0cbf036b242743b707706c721f8b9172188c3a9fa2709a478d40c9a89537405a4ae21df94e90d8ec24d0caa098db3c31d3d25d5414a5febf0e039da137440fa9dd932d759d3646040110270000000000002251202ec5640d3ba147e40c916e8fa9b0ee89557d10465db1d55a49c87edebe53104c8813000000000000225120c3731a9dc38c67dfa2dd206ee346d6225f1f37b97d77d518c59b9c9a291762288813000000000000225120a4ad17a5f329a164977981f1b7638c7a70b0dd1bed29a85637aed2952dd2e38c030256fda20ffb102f6cf8590d27433ce036d29927fb35324d15d9915df888f16ecd0357ccc0a609082b767909f37a4acdf55d1467bcaab77926b4ffe93edf8f9e8c4ea30a1bb9d23f32ee1c22e12a03c81a58f2c6b0c745e916bcbb2f6b46ca94830061050792ef121826fda248a789c8ba75b955844c65acd2c6361950bdd31dae7d0100020256fda20ffb102f6cf8590d27433ce036d29927fb35324d15d9915df888f16ecd9ea50d885c3f66d40d27e779648ba8dc730629663f65a3e6f7749b4a35b6dfecc28201002800ca6a1d9ccb57f92a11eb4383517f0046482462046eeb9090496785f1893b766f00000000").unwrap(),
		arkoor3_user_key: Keypair::from_str("ad12595bdbdab56cb61d1f60ccc46ff96b11c5d6fe06ae7ba03d3a5f4347440f").unwrap(),
		arkoor3_vtxo: ProtocolEncoding::deserialize_hex("01001027000000000000928a01000365a81233741893bbe2461b8d479dadc5880594fe6f7479180d5843820af72b62e007a3c23c49874159964c52b95021596d5a22e8f8b6bc7c16aa8303c24498d3d5ab00000000050108039e8a040d9c1fba5a7b0db8485d8f167f8d2590afd8595f9eb9ba7a769347ba2602bd0ad185b18089d37d20dd784b99003914faadcc59f37bbf3273a3b5cd22ed5002568a3a6d25000fc942f0443dc76be4ef688e8c8dc055591de1f2cc1c847b1ed3036e64c16a01e3d18908a15b55251a5db74ff2c1142c02abd048222893b2a18a16024ac23c8d3f6e0b1116e34f68ee7c9e4c19eba30213e8fae0925d70faf8d1ecc403932b1b0224e375471c938ea84bd17df7d8295941b2db68a6623610dd959b2eb303d215f5e88aefa7a2a9794771878f3d6caf20e884c1e0ce923cfa9dea261bb4e2024482039ebf3624525061f88aa01d4a02b3f2224eee8b4060ae0cbf036b242743d272c99b53de1036c5d3f381a6d873a759707ffc98414634943e8568ff9ddf3b57e658e0a5e0ad82daf82e783c1863aff6bccded8569199c1213e8c51407c0f6040388130000000000002251205acb7b65f8da14622a055640893e952e20f68e051087b85be4d56e50cdafd4318813000000000000225120973b9be7e6ee51f8851347130113e4001ab1d01252dd1d09713a6c900cb327f2881300000000000022512052cc228fe0f4951032fbaeb45ed8b73163cedb897412407e5b431d740040a9510105036e64c16a01e3d18908a15b55251a5db74ff2c1142c02abd048222893b2a18a16024ac23c8d3f6e0b1116e34f68ee7c9e4c19eba30213e8fae0925d70faf8d1ecc403932b1b0224e375471c938ea84bd17df7d8295941b2db68a6623610dd959b2eb303d215f5e88aefa7a2a9794771878f3d6caf20e884c1e0ce923cfa9dea261bb4e2024482039ebf3624525061f88aa01d4a02b3f2224eee8b4060ae0cbf036b242743b707706c721f8b9172188c3a9fa2709a478d40c9a89537405a4ae21df94e90d8ec24d0caa098db3c31d3d25d5414a5febf0e039da137440fa9dd932d759d3646040110270000000000002251202ec5640d3ba147e40c916e8fa9b0ee89557d10465db1d55a49c87edebe53104c8813000000000000225120c3731a9dc38c67dfa2dd206ee346d6225f1f37b97d77d518c59b9c9a291762288813000000000000225120a4ad17a5f329a164977981f1b7638c7a70b0dd1bed29a85637aed2952dd2e38c030256fda20ffb102f6cf8590d27433ce036d29927fb35324d15d9915df888f16ecd0357ccc0a609082b767909f37a4acdf55d1467bcaab77926b4ffe93edf8f9e8c4ea30a1bb9d23f32ee1c22e12a03c81a58f2c6b0c745e916bcbb2f6b46ca94830061050792ef121826fda248a789c8ba75b955844c65acd2c6361950bdd31dae7d010002010256fda20ffb102f6cf8590d27433ce036d29927fb35324d15d9915df888f16ecda3f46c1fa220865803e80a3688630644317f8c0a85491d849b4ce7f33d133ccf093c49954b4028aa6d3765b7d07eb6b92649a81a862f8ad39b97278bdefafff3632ac1f2f353abd646ae7d79707ea9ff0144ba8425762145932daef6bd8855bd010002010256fda20ffb102f6cf8590d27433ce036d29927fb35324d15d9915df888f16ecd565b73d5325e68949a264159ea1da8a7d8ba8788f3f63a202d5f3047d2fe9428e63ea5bd23c4524f59efb7213b3cde26f2fb8279f35e0f5b95d74576daa1d8c827af2054c993ea76819668d9b3d184cd48c521f1254e7a0ebeaa2f1b99a6f15d01000002ed1334f116cea9128e1f59f1d5a431cb4f338f0998e2b32f654c310bf7831f97016422a562a4826f26ff351ecb5b1122e0d27958053fd6595a9424a0305fad0700000000").unwrap(),
	};
}
