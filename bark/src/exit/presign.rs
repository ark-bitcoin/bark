//! Presigning emergency (unilateral) exit chains.
//!
//! Every not-yet-confirmed transaction in a VTXO's exit chain is zero-fee and carries a P2A
//! anchor, so each needs a fee-paying CPFP child to be broadcast.
//! [Exit::presign_emergency_exit] signs those children up front and returns the broadcast plan
//! as [PresignedExits], ready to execute later from cold storage or by a third party.

use std::collections::HashMap;

use bitcoin::{Amount, FeeRate, OutPoint, Transaction, Txid, Weight};

use ark::VtxoId;
use bitcoin_ext::{FeeRateExt, TransactionExt};

use crate::Wallet;
use crate::exit::{Exit, ExitError, FeeInfo, TransactionInfo};

/// How much of a [PresignedExit]'s remaining broadcast work could be funded and signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresignedExitStatus {
	/// Every package has a signed child; the exit's broadcast completes once wave
	/// `exited_in_wave` confirms (`None` when the chain is already confirmed and there is
	/// nothing to broadcast). `fee_info` totals the children's fees over the combined weight
	/// of this exit's packages.
	FullySigned { exited_in_wave: Option<usize>, fee_info: FeeInfo },
	/// Confirmed onchain funds ran out mid-chain: wave `last_wave` holds this exit's last
	/// signed package and [PresignedExit::unsigned] continues right after it.
	PartiallySigned { last_wave: usize },
	/// No package could be funded.
	Unsigned,
}

/// A signed CPFP child transaction and the fee it commits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresignedExitChildInfo {
	pub txid: Txid,
	pub tx: Transaction,
	/// The exit transaction is zero-fee, so this is the fee of the whole package.
	pub fee_info: FeeInfo,
}

/// An `(exit, child)` transaction package, to be broadcast as one unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresignedExitPackage {
	/// The VTXO whose exit this package advances.
	pub vtxo_id: VtxoId,
	/// The zero-fee exit transaction.
	pub exit: TransactionInfo,
	/// The signed CPFP child paying for `exit`.
	pub child: PresignedExitChildInfo,
}

/// One step of the broadcast plan; see [PresignedExits] for the rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresignedWave {
	/// Packages funded independently of each other, broadcast together.
	pub packages: Vec<PresignedExitPackage>,
	/// Exit transactions already in the mempool; they confirm with this wave. Only the first
	/// wave has any.
	pub in_mempool: Vec<TransactionInfo>,
}

/// The presigned broadcast work for one VTXO.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresignedExit {
	pub vtxo_id: VtxoId,
	pub status: PresignedExitStatus,
	/// The remaining tail of this exit's chain that could not be funded, in broadcast order;
	/// its first transaction spends this exit's last signed one. Empty when fully signed.
	pub unsigned: Vec<TransactionInfo>,
}

/// Presigned emergency-exit chains for a set of VTXOs: a wave-by-wave broadcast plan plus a
/// per-VTXO summary.
///
/// Execute the plan in wave order: broadcast all of a wave's packages together, then wait for
/// every one, and its `in_mempool` transactions, to confirm before the next wave — each
/// wave's children spend change confirmed by the previous wave.
///
/// Presigning reserves no funds, so a later spend from the onchain wallet can invalidate the
/// remaining children. It does reveal the change addresses those children pay to.
///
/// How much more funding a partial result would need is not reported, because adding funds
/// changes which coins the next child selects and therefore what it costs. Use the fee estimate
/// for that.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresignedExits {
	/// One entry per requested VTXO, in request order.
	pub exits: Vec<PresignedExit>,
	/// The broadcast plan. Confirmed transactions are omitted, relayed ones are listed in
	/// [PresignedWave::in_mempool], and a package shared by several exits appears once, under
	/// the first exit that references it.
	pub waves: Vec<PresignedWave>,
}

impl Exit {
	/// Signs a CPFP child for every exit transaction that still needs broadcasting for the given
	/// VTXOs, for as long as confirmed onchain funds last, and returns the broadcast plan.
	///
	/// Nothing is broadcast and no funds are reserved, but the onchain wallet does reveal the
	/// change addresses the children pay to — unlike fee estimation, which leaves it untouched.
	/// See [PresignedExits] for the broadcast rules. Duplicate ids resolve to their first
	/// occurrence; `fee_rate` defaults to [Exit::default_exit_fee_rate].
	///
	/// # Errors
	/// - [ExitError::UnknownVtxo] if a VTXO id isn't known to the wallet.
	/// - [ExitError::VtxoAlreadyExited] if a VTXO has already completed its exit.
	/// - [ExitError::VtxoAlreadySpent] if a VTXO was already spent (e.g. forfeited in a round).
	/// - [ExitError::InvalidWalletState] if the wallet has no onchain wallet configured.
	pub async fn presign_emergency_exit(
		&self,
		vtxos: &[VtxoId],
		wallet: &Wallet,
		fee_rate: Option<FeeRate>,
	) -> anyhow::Result<PresignedExits, ExitError> {
		let fee_rate = match fee_rate {
			Some(fr) => fr,
			None => self.default_exit_fee_rate().await,
		};

		let groups = self.collect_unconfirmed_exit_parents(vtxos).await?;
		let mut full_vtxos = Vec::with_capacity(groups.len());
		let mut exit_parents = Vec::with_capacity(groups.len());
		// Relayed packages need no child but gate whatever spends them.
		let mut relayed = Vec::new();
		let mut has_relayed = Vec::with_capacity(groups.len());
		for group in groups {
			let relayed_before = relayed.len();
			let mut parents = Vec::with_capacity(group.parents.len());
			for (tx, child) in group.parents {
				match child.required_cpfp_fees(fee_rate) {
					Some(fees) => parents.push((tx, fees)),
					None => relayed.push(TransactionInfo { txid: tx.compute_txid(), tx }),
				}
			}
			has_relayed.push(relayed.len() > relayed_before);
			full_vtxos.push(group.vtxo);
			exit_parents.push(parents);
		}

		let onchain = wallet.onchain()
			.ok_or_else(|| ExitError::InvalidWalletState {
				error: "no onchain wallet configured; cannot presign exit children".into(),
			})?;

		let mut walk_waves = if exit_parents.iter().all(Vec::is_empty) {
			Vec::new()
		} else {
			let relayed_txids = relayed.iter().map(|t| t.txid).collect::<Vec<_>>();
			onchain.write().await
				.presign_p2a_cpfp_walk(&exit_parents, &relayed_txids).await
				.map_err(|e| ExitError::InternalError { error: e.to_string() })?
		};
		// Relayed packages confirm with the first wave.
		if !relayed.is_empty() && walk_waves.is_empty() {
			walk_waves.push(Vec::new());
		}

		// Each child spends exactly one P2A anchor, identifying its parent and thus its exit.
		let mut anchors = HashMap::<OutPoint, (usize, usize)>::new();
		for (gi, parents) in exit_parents.iter().enumerate() {
			for (pi, (parent, _)) in parents.iter().enumerate() {
				let (point, _) = parent.fee_anchor()
					.ok_or(ExitError::MissingAnchorOutput { txid: parent.compute_txid() })?;
				anchors.insert(point, (gi, pi));
			}
		}

		// Wrap each signed child with its parent into a package, wave by wave, tallying per exit
		// how many packages were signed, the wave of the last one and the fee totals. The walk
		// signs each exit's packages in order, so the signed ones form a leading run of its
		// parents.
		let mut signed = vec![0usize; exit_parents.len()];
		let mut last_wave = vec![None; exit_parents.len()];
		let mut totals = vec![(Amount::ZERO, Weight::ZERO); exit_parents.len()];
		let mut waves = Vec::with_capacity(walk_waves.len());
		for (wi, walk_wave) in walk_waves.into_iter().enumerate() {
			let mut packages = Vec::with_capacity(walk_wave.len());
			for (child, fee) in walk_wave {
				let (gi, pi) = child.input.iter()
					.find_map(|input| anchors.get(&input.previous_output))
					.copied()
					.ok_or_else(|| ExitError::InternalError {
						error: format!(
							"presigned child {} spends no known exit anchor", child.compute_txid(),
						),
					})?;
				let parent = &exit_parents[gi][pi].0;
				let package_weight = parent.weight() + child.weight();
				signed[gi] += 1;
				last_wave[gi] = Some(wi);
				totals[gi].0 += fee;
				totals[gi].1 += package_weight;
				packages.push(PresignedExitPackage {
					vtxo_id: full_vtxos[gi].id(),
					exit: TransactionInfo { txid: parent.compute_txid(), tx: parent.clone() },
					child: PresignedExitChildInfo {
						txid: child.compute_txid(),
						fee_info: FeeInfo {
							fee_rate: FeeRate::from_amount_and_weight_ceil(fee, package_weight)
								.expect("package weight is non-zero"),
							total_fee: fee,
						},
						tx: child,
					},
				});
			}
			let in_mempool = if wi == 0 { std::mem::take(&mut relayed) } else { Vec::new() };
			waves.push(PresignedWave { packages, in_mempool });
		}

		// Summarize each exit: the parents past its signed run are the unsigned tail, and a fully
		// signed exit reports the fee its children commit over all of its packages.
		let mut exits = Vec::with_capacity(exit_parents.len());
		for (gi, parents) in exit_parents.into_iter().enumerate() {
			let signed = signed[gi];
			let unsigned = parents.into_iter().skip(signed)
				.map(|(parent, _)| TransactionInfo { txid: parent.compute_txid(), tx: parent })
				.collect::<Vec<_>>();
			let status = if unsigned.is_empty() {
				let (total_fee, total_weight) = totals[gi];
				let fee_rate = FeeRate::from_amount_and_weight_ceil(total_fee, total_weight)
					.unwrap_or(FeeRate::ZERO);
				PresignedExitStatus::FullySigned {
					// A relayed package precedes any signed one in its chain.
					exited_in_wave: last_wave[gi].or(has_relayed[gi].then_some(0)),
					fee_info: FeeInfo { fee_rate, total_fee },
				}
			} else if signed > 0 {
				let last_wave = last_wave[gi].expect("signed packages have a wave");
				PresignedExitStatus::PartiallySigned { last_wave }
			} else {
				PresignedExitStatus::Unsigned
			};
			exits.push(PresignedExit { vtxo_id: full_vtxos[gi].id(), status, unsigned });
		}

		Ok(PresignedExits { exits, waves })
	}
}
