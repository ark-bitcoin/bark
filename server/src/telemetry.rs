
use std::fmt;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bitcoin::secp256k1::PublicKey;
use bitcoin::{Amount, Network};
use bitcoin_ext::bdk::TrustedBalance;
use bitcoin::hex::DisplayHex;
use bitcoin_ext::BlockHeight;
use opentelemetry::global::BoxedSpan;
use opentelemetry::metrics::{Counter, Gauge, Histogram, UpDownCounter};
use opentelemetry::{Key, Value};
use opentelemetry::{global, KeyValue};
use opentelemetry::trace::{Span, SpanRef, TracerProvider};
use opentelemetry_otlp::{Compression, WithExportConfig, WithTonicConfig};
use opentelemetry_sdk::error::OTelSdkResult;
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::trace::{BatchSpanProcessor, RandomIdGenerator, Sampler, SpanData, SpanExporter};
use tokio::time::Instant;
use tracing::warn;
use tracing_core::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;
use smallvec::SmallVec;
use ark::mailbox::MailboxType;
use ark::VtxoId;
use ark::rounds::RoundSeq;

use crate::database::ln::{LightningHtlcSubscriptionStatus, LightningPaymentStatus};
use crate::ln::node_manager::NodeStateKind;
use crate::round::RoundStateKind;
use crate::wallet::WalletKind;

pub const TRACE_GRPC: &str = "grpc";
pub const TRACE_RUN_ROUND: &str = "round";

pub const TRACE_RUN_ROUND_ATTEMPT: &str = "round_attempt";
pub const TRACE_RUN_ROUND_POPULATED: &str = "round_populated";

pub const ATTRIBUTE_WORKER: &str = "worker";
pub const ATTRIBUTE_STATUS: &str = "status";
pub const ATTRIBUTE_ERROR: &str = "error";
pub const ATTRIBUTE_TYPE: &str = "type";
pub const ATTRIBUTE_KIND: &str = "kind";
pub const ATTRIBUTE_URI: &str = "uri";
pub const ATTRIBUTE_PUBKEY: &str = "pubkey";
pub const ATTRIBUTE_SERVER_VERSION: &str = "server_version";
pub const ATTRIBUTE_BARK_VERSION: &str = "bark_version";
pub const ATTRIBUTE_PROTOCOL_VERSION: &str = "protocol_version";
pub const ATTRIBUTE_ROUND_ID: &str = "round_id";
pub const ATTRIBUTE_ROUND_SEQ: &str = "round_seq";
pub const ATTRIBUTE_ATTEMPT_SEQ: &str = "attempt_seq";
pub const ATTRIBUTE_ROUND_STEP: &str = "round_step";
pub const ATTRIBUTE_LIGHTNING_NODE_ID: &str = "lightning_node_id";


pub trait MetricsService {
	const NAME: &'static str;
	const TRACER: &'static str;
	const METER: &'static str;
	const LOG_ENV_VAR: &'static str;
}

/// [MetricsService] for captaind
pub struct Captaind;

impl MetricsService for Captaind {
	const NAME: &'static str = "captaind";
	const TRACER: &'static str = "captaind";
	const METER: &'static str = "captaind";
	const LOG_ENV_VAR: &'static str = "CAPTAIND_LOG";
}

/// [MetricsService] for watchmand
pub struct Watchmand;

impl MetricsService for Watchmand {
	const NAME: &'static str = "watchmand";
	const TRACER: &'static str = "watchmand";
	const METER: &'static str = "watchmand";
	const LOG_ENV_VAR: &'static str = "WATCHMAND_LOG";
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum RoundStep {
	AttemptInitiation,
	ReceivePayments,
	ConstructVtxoTree,
	SendingVtxoProposal,
	ReceiveVtxoSignatures,
	CombineVtxoSignatures,
	ConstructRoundProposal,
	ReceiveForfeitSignatures,
	FinalStage,
	SignOnChainTransaction,
	BroadcastOnChainTransaction,
	Persist,
}

#[derive(Clone, Copy)]
pub struct TimedRoundStep {
	round_seq: RoundSeq,
	attempt_seq: usize,
	step: RoundStep,
	instant: Instant,
}

impl RoundStep {
	pub fn with_instant(self, round_seq: RoundSeq, attempt_seq: usize) -> TimedRoundStep {
		TimedRoundStep {
			round_seq,
			attempt_seq,
			step: self,
			instant: Instant::now(),
		}
	}

	pub const ATTEMPT_INITIATION: &'static str = "round_attempt";
	pub const RECEIVE_PAYMENTS: &'static str = "round_receive_payments";
	pub const CONSTRUCT_VTXO_TREE: &'static str = "round_construct_vtxo_tree";
	pub const SENDING_VTXO_PROPOSAL: &'static str = "round_sending_vtxo_proposal";
	pub const RECEIVE_VTXO_SIGNATURES: &'static str = "round_receive_vtxo_signatures";
	pub const COMBINE_VTXO_SIGNATURES: &'static str = "round_combine_vtxo_signatures";
	pub const CONSTRUCT_ROUND_PROPOSAL: &'static str = "round_construct_round_proposal";
	pub const RECEIVE_FORFEIT_SIGNATURES: &'static str = "round_receive_forfeit_signatures";
	pub const FINAL_STAGE: &'static str = "round_finalize_stage";
	pub const SIGN_ON_CHAIN_TRANSACTION: &'static str = "round_sign_on_chain_transaction";
	pub const BROADCAST_TX: &'static str = "round_broadcast_tx";
	pub const PERSIST: &'static str = "round_persist";

	// When changing this also change `get_all`

	pub fn as_str(&self) -> &'static str {
		match self {
			RoundStep::AttemptInitiation => Self::ATTEMPT_INITIATION,
			RoundStep::ReceivePayments => Self::RECEIVE_PAYMENTS,
			RoundStep::ConstructVtxoTree => Self::CONSTRUCT_VTXO_TREE,
			RoundStep::SendingVtxoProposal => Self::SENDING_VTXO_PROPOSAL,
			RoundStep::ReceiveVtxoSignatures => Self::RECEIVE_VTXO_SIGNATURES,
			RoundStep::CombineVtxoSignatures => Self::COMBINE_VTXO_SIGNATURES,
			RoundStep::ConstructRoundProposal => Self::CONSTRUCT_ROUND_PROPOSAL,
			RoundStep::ReceiveForfeitSignatures => Self::RECEIVE_FORFEIT_SIGNATURES,
			RoundStep::FinalStage => Self::FINAL_STAGE,
			RoundStep::SignOnChainTransaction => Self::SIGN_ON_CHAIN_TRANSACTION,
			RoundStep::BroadcastOnChainTransaction => Self::BROADCAST_TX,
			RoundStep::Persist => Self::PERSIST,
		}
	}

	pub fn get_all() -> &'static [RoundStep] {
		&[
			RoundStep::AttemptInitiation,
			RoundStep::ReceivePayments,
			RoundStep::ConstructVtxoTree,
			RoundStep::SendingVtxoProposal,
			RoundStep::ReceiveVtxoSignatures,
			RoundStep::CombineVtxoSignatures,
			RoundStep::ConstructRoundProposal,
			RoundStep::ReceiveForfeitSignatures,
			RoundStep::FinalStage,
			RoundStep::SignOnChainTransaction,
			RoundStep::BroadcastOnChainTransaction,
			RoundStep::Persist,
		]
	}
}

impl TimedRoundStep {
	pub fn round_seq(&self) -> RoundSeq {
		self.round_seq
	}

	pub fn attempt_seq(&self) -> usize {
		self.attempt_seq
	}

	pub fn duration(&self) -> Duration {
		Instant::now().duration_since(self.instant)
	}

	pub fn as_str(&self) -> &'static str {
		self.step.as_str()
	}

	pub fn proceed(&self, round_step: RoundStep) -> TimedRoundStep {
		round_step.with_instant(self.round_seq, self.attempt_seq)
	}
}

pub const SERVICE_NAME: &str = opentelemetry_semantic_conventions::attribute::SERVICE_NAME;
pub const SERVICE_VERSION: &str = opentelemetry_semantic_conventions::attribute::SERVICE_VERSION;
pub const RPC_SYSTEM: &str = opentelemetry_semantic_conventions::attribute::RPC_SYSTEM;
pub const RPC_SERVICE: &str = opentelemetry_semantic_conventions::attribute::RPC_SERVICE;
pub const RPC_METHOD: &str = opentelemetry_semantic_conventions::attribute::RPC_METHOD;
#[deprecated(
	since = "0.2.4",
	note = "access tokens are not enforced by the server; this label will be removed",
)]
pub const RPC_ACCESS_TOKEN: &str = "rpc.access_token";
/// Client implementation that issued the RPC, bucketed to a small allowlist
/// to bound metric cardinality (see `rpcserver::middleware::bucket_client`).
pub const RPC_CLIENT: &str = "rpc.client";
/// The [numeric status code](https://github.com/grpc/grpc/blob/v1.33.2/doc/statuscodes.md)
/// of the gRPC request.
pub const RPC_GRPC_STATUS_CODE: &str = opentelemetry_semantic_conventions::attribute::RPC_GRPC_STATUS_CODE;

tokio::task_local! {
	/// The bucketed client name (parsed from `x-user-agent` by
	/// `rpcserver::middleware::bucket_client`) for the currently-serving RPC.
	/// Set by the telemetry middleware around each request's future; read by
	/// business-metric emitters that want a per-integrator label. Outside a
	/// scope [current_client] returns `"unknown"`.
	pub static CLIENT: &'static str;
}

/// Return the bucketed client name for the currently-serving RPC, or
/// `"unknown"` when called outside an RPC context (background workers,
/// startup, tests). Safe to sprinkle onto any metric attribute list; the
/// underlying `&'static str` is bounded by [rpcserver::middleware::bucket_client]
/// so cardinality stays capped.
pub fn current_client() -> &'static str {
	CLIENT.try_with(|c| *c).unwrap_or("unknown")
}

/// The global open-telemetry context to register metrics.
static TELEMETRY: tokio::sync::OnceCell<Metrics> = tokio::sync::OnceCell::const_new();
static BLOCK_HEIGHT_TIP: AtomicU64 = AtomicU64::new(0);
static SYNC_HEIGHT_TIP: AtomicU64 = AtomicU64::new(0);

/// Initialize open-telemetry.
///
/// MUST be called (only once) before registering or updating metrics.
pub fn init_telemetry<S: MetricsService>(
	endpoint: Option<String>,
	otel_tracing_sampler: Option<f64>,
	otel_deployment_name: &str,
	network: Network,
	round_interval: Duration,
	max_vtxo_amount: Option<Amount>,
	server_pubkey: PublicKey,
) {
	let _ = TELEMETRY.set(Metrics::init::<S>(
		endpoint,
		otel_tracing_sampler,
		otel_deployment_name,
		network,
		round_interval,
		max_vtxo_amount,
		server_pubkey,
	));
}

#[derive(Debug)]
struct Metrics {
	spawn_counter: UpDownCounter<i64>,
	bark_version_counter: Counter<u64>,
	protocol_version_counter: Counter<u64>,
	wallet_balance_gauge: Gauge<u64>,
	block_height_gauge: Gauge<u64>,
	sync_height_gauge: Gauge<u64>,
	round_seq_gauge: Gauge<u64>,
	round_state_gauge: Gauge<u64>,
	round_step_duration_gauge: Gauge<u64>,
	round_attempt_gauge: Gauge<u64>,
	round_input_volume_gauge: Gauge<u64>,
	round_input_count_gauge: Gauge<u64>,
	round_output_count_gauge: Gauge<u64>,
	mailbox_counter: Counter<u64>,
	lightning_node_gauge: Gauge<u64>,
	lightning_node_boot_counter: Counter<u64>,
	lightning_payment_counter: Counter<u64>,
	lightning_payment_volume: Counter<u64>,
	arkoor_payment_counter: Counter<u64>,
	arkoor_payment_volume: Counter<u64>,
	board_counter: Counter<u64>,
	board_volume: Counter<u64>,
	offboard_counter: Counter<u64>,
	offboard_volume: Counter<u64>,
	round_counter: Counter<u64>,
	round_volume: Counter<u64>,
	refresh_counter: Counter<u64>,
	refresh_volume: Counter<u64>,
	delegated_participation_counter: Counter<u64>,
	delegated_participation_volume: Counter<u64>,
	round_output_pubkey_counter: Counter<u64>,
	round_output_pubkey_volume: Counter<u64>,
	round_output_htlc_send_counter: Counter<u64>,
	round_output_htlc_send_volume: Counter<u64>,
	round_output_htlc_recv_counter: Counter<u64>,
	round_output_htlc_recv_volume: Counter<u64>,
	unilateral_exit_counter: Counter<u64>,
	unilateral_exit_volume: Counter<u64>,
	lightning_invoice_verification_counter: Counter<u64>,
	lightning_invoice_verification_queue_gauge: Gauge<u64>,
	lightning_open_invoices_gauge: Gauge<u64>,
	vtxo_pool_expiry_blocks_bucket_gauge: Gauge<u64>,
	vtxo_pool_expiry_blocks_count_gauge: Gauge<u64>,
	vtxo_pool_expiry_blocks_sum_gauge: Gauge<u64>,
	vtxo_pool_expiry_sats_bucket_gauge: Gauge<u64>,
	vtxo_pool_expiry_sats_count_gauge: Gauge<u64>,
	vtxo_pool_expiry_sats_sum_gauge: Gauge<u64>,
	vtxo_pool_amount_bucket_gauge: Gauge<u64>,
	vtxo_pool_amount_count_gauge: Gauge<u64>,
	vtxo_pool_amount_sum_gauge: Gauge<u64>,
	vtxo_pool_amount_sats_bucket_gauge: Gauge<u64>,
	frontier_gauge: Gauge<u64>,
	grpc_in_progress_counter: UpDownCounter<i64>,
	grpc_latency_histogram: Histogram<u64>,
	grpc_request_counter: Counter<u64>,
	grpc_error_counter: Counter<u64>,
	postgres_connections: Gauge<u64>,
	postgres_idle_connections: Gauge<u64>,
	postgres_connections_created: Gauge<u64>,
	postgres_connections_closed_broken: Gauge<u64>,
	postgres_connections_closed_idle_timeout: Gauge<u64>,
	postgres_connections_closed_invalid: Gauge<u64>,
	postgres_connections_closed_max_lifetime: Gauge<u64>,
	postgres_get_direct: Gauge<u64>,
	postgres_get_timed_out: Gauge<u64>,
	postgres_get_waited: Gauge<u64>,
	postgres_get_wait_time: Gauge<u64>,
	fee_rate_gauge: Gauge<f64>,
	fee_rate_using_fallback_gauge: Gauge<u64>,
	tokio_runtime_delay_histogram: Histogram<u64>,
	ark_protocol_fee_sat_counter: Counter<u64>,
	global_labels: Vec<KeyValue>,
}

#[derive(Debug, Default)]
struct NoopSpanExporter;

impl SpanExporter for NoopSpanExporter {
	fn export(&self, _batch: Vec<SpanData>) -> impl Future<Output=OTelSdkResult> + Send {
		async move { Ok(()) }
	}
}

impl Metrics {
	fn init<S: MetricsService>(
		endpoint: Option<String>,
		otel_tracing_sampler: Option<f64>,
		otel_deployment_name: &str,
		network: Network,
		round_interval: Duration,
		max_vtxo_amount: Option<Amount>,
		server_pubkey: PublicKey,
	) -> Self {
		global::set_text_map_propagator(TraceContextPropagator::new());

		let span_processor = match endpoint.clone() {
			Some(endpoint) if !endpoint.trim().is_empty() => {
				match opentelemetry_otlp::SpanExporter::builder()
					.with_tonic()
					.with_endpoint(endpoint)
					.with_timeout(Duration::from_secs(10))
					.with_compression(Compression::Gzip)
					.build() {
					Ok(exporter) => {
						BatchSpanProcessor::builder(exporter).build()
					}
					Err(_err) => {
						BatchSpanProcessor::builder(NoopSpanExporter).build()
					}
				}
			}
			_ => {
				BatchSpanProcessor::builder(NoopSpanExporter).build()
			}
		};

		let resource = Resource::builder()
			.with_attribute(KeyValue::new(SERVICE_NAME, S::NAME))
			.with_attribute(KeyValue::new(SERVICE_VERSION, env!("CARGO_PKG_VERSION")))
			.with_attribute(KeyValue::new(
				format!("{}.pubkey", S::NAME),
				server_pubkey.to_string(),
			))
			.with_attribute(KeyValue::new(
				format!("{}.network", S::NAME),
				network.to_string(),
			))
			.with_attribute(KeyValue::new(
				format!("{}.otel_deployment_name", S::NAME),
				otel_deployment_name.to_string(),
			))
			.with_attribute(KeyValue::new(
				format!("{}.round_interval", S::NAME),
				round_interval.as_secs().to_string(),
			))
			.with_attribute(KeyValue::new(
				format!("{}.maximum_vtxo_amount", S::NAME),
				max_vtxo_amount.unwrap_or_else(|| Amount::ZERO).to_string(),
			))
			.build();

		let tracer_sampler = otel_tracing_sampler.map(Sampler::TraceIdRatioBased)
			.unwrap_or(Sampler::AlwaysOn);

		let tracer_provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
			.with_span_processor(span_processor)
			.with_sampler(tracer_sampler)
			.with_id_generator(RandomIdGenerator::default())
			.with_max_events_per_span(64)
			.with_max_attributes_per_span(16)
			.with_resource(resource.clone())
			.build();

		let tracer = tracer_provider.tracer(S::TRACER);

		let mut filter = EnvFilter::from_default_env()
			.add_directive(LevelFilter::TRACE.into())
			.add_directive("rustls=WARN".parse().unwrap())
			.add_directive("bitcoincore_rpc=WARN".parse().unwrap())
			.add_directive("bitcoind_async_client=WARN".parse().unwrap())
			.add_directive("tokio_postgres=INFO".parse().unwrap())
			.add_directive("tonic=INFO".parse().unwrap())
			.add_directive("tower=INFO".parse().unwrap())
			.add_directive("opentelemetry-otlp=INFO".parse().unwrap())
			.add_directive("opentelemetry_sdk=INFO".parse().unwrap())
			.add_directive("h2=INFO".parse().unwrap());
		if let Ok(env_str) = std::env::var(S::LOG_ENV_VAR) {
			for part in env_str.split(',') {
				let part = part.trim();
				if !part.is_empty() {
					if let Ok(d) = part.parse() {
						filter = filter.add_directive(d);
					}
				}
			}
		}

		let registry = tracing_subscriber::registry()
			.with(filter)
			.with(server_log::slog_json_layer(std::io::stdout))
			.with(tracing_opentelemetry::layer().with_tracer(tracer));

		// Spawns the console-subscriber server (default 127.0.0.1:6669) and
		// returns a layer that captures the tokio runtime trace events that
		// `tokio-console` consumes. Honours TOKIO_CONSOLE_BIND etc.
		#[cfg(feature = "tokio-console")]
		let registry = registry.with(console_subscriber::spawn());

		match registry.try_init() {
			Ok(()) => {
				global::set_tracer_provider(tracer_provider);

				match endpoint {
					Some(endpoint) if !endpoint.trim().is_empty() => {
						let metrics_exporter = opentelemetry_otlp::MetricExporter::builder()
							.with_tonic()
							.with_endpoint(endpoint)
							.with_timeout(Duration::from_secs(10))
							.with_compression(Compression::Gzip)
							.build().unwrap();

						let metrics_reader = PeriodicReader::builder(metrics_exporter).build();
						let provider = SdkMeterProvider::builder()
							.with_reader(metrics_reader)
							.with_resource(resource)
							.build();
						global::set_meter_provider(provider);
					}
					_ => {
						let provider = SdkMeterProvider::builder()
							.with_resource(resource)
							.build();
						global::set_meter_provider(provider);
					}
				}
			}
			Err(_e) => { }
		}

		let meter = global::meter_provider().meter(S::METER);
		let spawn_counter = meter.i64_up_down_counter("spawn_counter").build();
		let bark_version_counter = meter.u64_counter("bark_version_counter").build();
		let protocol_version_counter = meter.u64_counter("protocol_version_counter").build();
		let wallet_balance_gauge = meter.u64_gauge("wallet_balance_gauge").build();
		let block_height_gauge = meter.u64_gauge("block_gauge").build();
		let sync_height_gauge = meter.u64_gauge("sync_height_gauge").build();
		let round_seq_gauge = meter.u64_gauge("round_seq_gauge").build();
		let round_state_gauge = meter.u64_gauge("round_state_gauge").build();
		let round_step_duration_gauge = meter.u64_gauge("round_step_duration_gauge").build();
		let round_attempt_gauge = meter.u64_gauge("round_attempt_gauge").build();
		let round_input_volume_gauge = meter.u64_gauge("round_input_volume_gauge").build();
		let round_input_count_gauge = meter.u64_gauge("round_input_count_gauge").build();
		let round_output_count_gauge = meter.u64_gauge("round_output_count_gauge").build();
		let mailbox_counter = meter.u64_counter("mailbox_counter").build();
		let lightning_node_gauge = meter.u64_gauge("lightning_node_gauge").build();
		let lightning_node_boot_counter = meter.u64_counter("lightning_node_boot_counter").build();
		let lightning_payment_counter = meter.u64_counter("lightning_payment_counter").build();
		let lightning_payment_volume = meter.u64_counter("lightning_payment_volume").build();
		let arkoor_payment_counter = meter.u64_counter("arkoor_payment_counter").build();
		let arkoor_payment_volume = meter.u64_counter("arkoor_payment_volume").build();
		let board_counter = meter.u64_counter("board_counter").build();
		let board_volume = meter.u64_counter("board_volume").build();
		let offboard_counter = meter.u64_counter("offboard_counter").build();
		let offboard_volume = meter.u64_counter("offboard_volume").build();
		let round_counter = meter.u64_counter("round_counter").build();
		let round_volume = meter.u64_counter("round_volume").build();
		let refresh_counter = meter.u64_counter("refresh_counter")
			.with_description("Refresh participations (one per interactive SubmitPayment that recycles existing VTXOs into a round)")
			.build();
		let refresh_volume = meter.u64_counter("refresh_volume")
			.with_description("Volume of inputs recycled via interactive round participations, in sats")
			.with_unit("sat")
			.build();
		let delegated_participation_counter = meter.u64_counter("delegated_participation_counter")
			.with_description("Delegated round participations (server-submitted on behalf of users, e.g. LN HTLC settlements landing in a round); one per participation included in a successful round")
			.build();
		let delegated_participation_volume = meter.u64_counter("delegated_participation_volume")
			.with_description("Volume of inputs consumed via delegated round participations, in sats")
			.with_unit("sat")
			.build();
		let round_output_pubkey_counter = meter.u64_counter("round_output_pubkey_counter")
			.with_description("VTXOs created by a successful round with a pubkey policy (excludes server-generated padding)")
			.build();
		let round_output_pubkey_volume = meter.u64_counter("round_output_pubkey_volume")
			.with_description("Volume of pubkey-policy VTXOs created by successful rounds, in sats")
			.with_unit("sat")
			.build();
		let round_output_htlc_send_counter = meter.u64_counter("round_output_htlc_send_counter")
			.with_description("VTXOs created by a successful round with the server-htlc-send policy")
			.build();
		let round_output_htlc_send_volume = meter.u64_counter("round_output_htlc_send_volume")
			.with_description("Volume of server-htlc-send VTXOs created by successful rounds, in sats")
			.with_unit("sat")
			.build();
		let round_output_htlc_recv_counter = meter.u64_counter("round_output_htlc_recv_counter")
			.with_description("VTXOs created by a successful round with the server-htlc-recv policy")
			.build();
		let round_output_htlc_recv_volume = meter.u64_counter("round_output_htlc_recv_volume")
			.with_description("Volume of server-htlc-recv VTXOs created by successful rounds, in sats")
			.with_unit("sat")
			.build();
		let unilateral_exit_counter = meter.u64_counter("unilateral_exit_counter")
			.with_description("Unilateral exits observed on-chain (one per frontier VTXO whose funding tx first confirms)")
			.build();
		let unilateral_exit_volume = meter.u64_counter("unilateral_exit_volume")
			.with_description("Total VTXO value (sats) observed exiting unilaterally on-chain")
			.with_unit("sat")
			.build();
		let lightning_invoice_verification_counter = meter.u64_counter("lightning_invoice_verification_counter").build();
		let lightning_invoice_verification_queue_gauge = meter.u64_gauge("lightning_invoice_verification_queue_gauge").build();
		let lightning_open_invoices_gauge = meter.u64_gauge("lightning_open_invoices_gauge").build();
		// Prometheus-histogram-shaped view of the VTXO pool by blocks-until-expiry.
		// Two families share `le`-labeled cumulative buckets over
		// [EXPIRY_HISTOGRAM_BOUNDARIES]: `_blocks_` observes one value per VTXO
		// (blocks_until_expiry) so its buckets, sum, and count follow Prom
		// histogram conventions; `_sats_` uses the same `le` axis but sums sats
		// per VTXO, so `_sats_bucket{le="144"}` reads as "sats past the wallet
		// refresh threshold". `_sats_sum` is total pool sats. Values are absolute
		// snapshots recorded on every scrape, not monotonic counters, so treat
		// them as gauges shaped like histogram output rather than true event
		// histograms; standard `_bucket{le="X"}` queries work, but
		// `histogram_quantile(rate(...))` does not.
		let vtxo_pool_expiry_blocks_bucket_gauge = meter.u64_gauge("vtxo_pool_expiry_blocks_bucket")
			.with_description("VTXO count with blocks_until_expiry <= le (Prom histogram bucket schema, gauge)")
			.build();
		let vtxo_pool_expiry_blocks_count_gauge = meter.u64_gauge("vtxo_pool_expiry_blocks_count")
			.with_description("Total VTXO count in the pool (matches _blocks_bucket{le=+Inf})")
			.build();
		let vtxo_pool_expiry_blocks_sum_gauge = meter.u64_gauge("vtxo_pool_expiry_blocks_sum")
			.with_description("Sum of blocks_until_expiry across all VTXOs in the pool")
			.build();
		let vtxo_pool_expiry_sats_bucket_gauge = meter.u64_gauge("vtxo_pool_expiry_sats_bucket")
			.with_description("VTXO sat total with blocks_until_expiry <= le (Prom histogram bucket schema, gauge)")
			.build();
		let vtxo_pool_expiry_sats_count_gauge = meter.u64_gauge("vtxo_pool_expiry_sats_count")
			.with_description("Total VTXO count (same as _blocks_count, kept for schema symmetry)")
			.build();
		let vtxo_pool_expiry_sats_sum_gauge = meter.u64_gauge("vtxo_pool_expiry_sats_sum")
			.with_description("Total sats in the pool (matches _sats_bucket{le=+Inf})")
			.build();
		// Prometheus-histogram-shaped view of the VTXO pool by amount. `_bucket`
		// is a natural histogram observing amount per VTXO, so `_sum` is total
		// sats and `histogram_quantile` gives median/quantile VTXO size.
		// `_sats_bucket{le="X"}` is the custom-shaped counterpart that gives
		// cumulative sats in VTXOs at or under X (useful for "sats in dust").
		// The `le` axis is derived from the fixed [AMOUNT_HISTOGRAM_BOUNDARIES]
		// plus `+Inf`, not from `config.vtxo_targets`, so labels are stable
		// across deployments and cross-deployment dashboards share the same
		// axis. Values are snapshots on every scrape, not monotonic counters;
		// standard bucket queries work, but `histogram_quantile(rate(...))`
		// does not.
		let vtxo_pool_amount_bucket_gauge = meter.u64_gauge("vtxo_pool_amount_bucket")
			.with_description("VTXO count with amount <= le (Prom histogram bucket schema, gauge)")
			.build();
		let vtxo_pool_amount_count_gauge = meter.u64_gauge("vtxo_pool_amount_count")
			.with_description("Total VTXO count in the pool (matches _amount_bucket{le=+Inf})")
			.build();
		let vtxo_pool_amount_sum_gauge = meter.u64_gauge("vtxo_pool_amount_sum")
			.with_description("Total sats in the pool (matches Prom histogram _sum)")
			.build();
		let vtxo_pool_amount_sats_bucket_gauge = meter.u64_gauge("vtxo_pool_amount_sats_bucket")
			.with_description("Sats in VTXOs with amount <= le (Prom histogram bucket schema, gauge)")
			.build();
		let frontier_gauge = meter.u64_gauge("frontier_gauge")
			.with_description("Unswept frontier VTXO value in sats, labeled by watchman action")
			.build();
		// gRPC metrics
		let grpc_in_progress_counter = meter.i64_up_down_counter("grpc_requests_in_progress").build();
		let grpc_latency_histogram = meter.u64_histogram("grpc_request_duration_ms").build();
		let grpc_request_counter = meter.u64_counter("grpc_requests_total").build();
		let grpc_error_counter = meter.u64_counter("grpc_errors_total").build();
		// postgres metrics
		let postgres_connections = meter.u64_gauge("postgres_connections").build();
		let postgres_idle_connections = meter.u64_gauge("postgres_idle_connections").build();
		let postgres_connections_created = meter.u64_gauge("postgres_connections_created").build();
		let postgres_connections_closed_broken = meter.u64_gauge("postgres_connections_closed_broken").build();
		let postgres_connections_closed_idle_timeout = meter.u64_gauge("postgres_connections_closed_idle_timeout").build();
		let postgres_connections_closed_invalid = meter.u64_gauge("postgres_connections_closed_invalid").build();
		let postgres_connections_closed_max_lifetime = meter.u64_gauge("postgres_connections_closed_max_lifetime").build();
		let postgres_get_direct = meter.u64_gauge("postgres_get_direct").build();
		let postgres_get_timed_out = meter.u64_gauge("postgres_get_timed_out").build();
		let postgres_get_waited = meter.u64_gauge("postgres_get_waited").build();
		let postgres_get_wait_time = meter.u64_gauge("postgres_get_wait_time").build();
		// fee estimator metrics
		let fee_rate_gauge = meter.f64_gauge("fee_rate")
			.with_description("Estimated fee rate (use 'estimator' label: fast/regular/slow)")
			.with_unit("sat/vb")
			.build();
		let fee_rate_using_fallback_gauge = meter.u64_gauge("fee_rate_using_fallback")
			.with_description("Whether fallback fee rates are being used (0=estimated, 1=fallback)")
			.build();
		// 100ms is the sleep floor; buckets grow from there. Anything below 100
		// is clock skew, anything above tracks runtime stalls of increasing severity.
		let tokio_runtime_delay_histogram = meter.u64_histogram("tokio_runtime_delay_ms")
			.with_description("Tokio runtime poll delay: time a 100ms sleep actually took")
			.with_unit("ms")
			.with_boundaries(vec![100.0, 105.0, 110.0, 125.0, 150.0, 200.0, 300.0, 500.0, 1000.0, 2000.0, 5000.0])
			.build();

		let ark_protocol_fee_sat_counter = meter.u64_counter("ark_protocol_fee_sat")
			.with_description("Ark protocol fees in sats, labeled by op_type. \
				For lightning_send the value is the net margin (quoted fee - routing fee).")
			.build();

		// log the current server version
		meter.u64_counter("server_version_counter").build().add(
			1u64, &[
				KeyValue::new(ATTRIBUTE_SERVER_VERSION, env!("CARGO_PKG_VERSION")),
				KeyValue::new("otel_deployment_name", otel_deployment_name.to_string()),
				KeyValue::new("network", network.to_string()),
			],
		);

		let global_labels = vec![
			KeyValue::new("otel_deployment_name", otel_deployment_name.to_string()),
			KeyValue::new("network", network.to_string()),
		];

		Metrics {
			spawn_counter,
			bark_version_counter,
			protocol_version_counter,
			wallet_balance_gauge,
			block_height_gauge,
			sync_height_gauge,
			round_seq_gauge,
			round_state_gauge,
			round_step_duration_gauge,
			round_attempt_gauge,
			round_input_volume_gauge,
			round_input_count_gauge,
			round_output_count_gauge,
			mailbox_counter,
			lightning_node_gauge,
			lightning_node_boot_counter,
			lightning_payment_counter,
			lightning_payment_volume,
			arkoor_payment_counter,
			arkoor_payment_volume,
			board_counter,
			board_volume,
			offboard_counter,
			offboard_volume,
			round_counter,
			round_volume,
			refresh_counter,
			refresh_volume,
			delegated_participation_counter,
			delegated_participation_volume,
			round_output_pubkey_counter,
			round_output_pubkey_volume,
			round_output_htlc_send_counter,
			round_output_htlc_send_volume,
			round_output_htlc_recv_counter,
			round_output_htlc_recv_volume,
			unilateral_exit_counter,
			unilateral_exit_volume,
			lightning_invoice_verification_counter,
			lightning_invoice_verification_queue_gauge,
			lightning_open_invoices_gauge,
			vtxo_pool_expiry_blocks_bucket_gauge,
			vtxo_pool_expiry_blocks_count_gauge,
			vtxo_pool_expiry_blocks_sum_gauge,
			vtxo_pool_expiry_sats_bucket_gauge,
			vtxo_pool_expiry_sats_count_gauge,
			vtxo_pool_expiry_sats_sum_gauge,
			vtxo_pool_amount_bucket_gauge,
			vtxo_pool_amount_count_gauge,
			vtxo_pool_amount_sum_gauge,
			vtxo_pool_amount_sats_bucket_gauge,
			frontier_gauge,
			grpc_in_progress_counter,
			grpc_latency_histogram,
			grpc_request_counter,
			grpc_error_counter,
			postgres_connections,
			postgres_idle_connections,
			postgres_connections_created,
			postgres_connections_closed_broken,
			postgres_connections_closed_idle_timeout,
			postgres_connections_closed_invalid,
			postgres_connections_closed_max_lifetime,
			postgres_get_direct,
			postgres_get_timed_out,
			postgres_get_waited,
			postgres_get_wait_time,
			fee_rate_gauge,
			fee_rate_using_fallback_gauge,
			tokio_runtime_delay_histogram,
			ark_protocol_fee_sat_counter,
			global_labels,
		}
	}

	fn global_labels(&self) -> &[KeyValue] {
		&self.global_labels
	}

	fn with_global_labels<I>(&self, additional: I) -> SmallVec<[KeyValue; 10]>
	where
		I: IntoIterator<Item = KeyValue>,
	{
		// Using SmallVec to avoid heap allocations for up to 10 attributes.
		// Maximum observed: 2 global labels + 8 additional = 10 total
		// This stores everything on the stack for <= 10 attributes!
		let mut attrs = SmallVec::<[KeyValue; 10]>::new();

		// Copy global labels to stack buffer
		for kv in &self.global_labels {
			attrs.push(kv.clone());
		}

		// Copy additional attributes
		for kv in additional {
			attrs.push(kv);
		}

		// Warn if we're causing heap allocation (more than 10 total attributes)
		if attrs.len() > 10 {
			warn!(
				"Telemetry attributes exceeded stack allocation limit: {} attributes will cause heap allocation",
				attrs.len(),
			);
		}

		attrs
	}
}

pub fn worker_spawned(worker: &str) {
	if let Some(m) = TELEMETRY.get() {
		let attrs = m.with_global_labels([KeyValue::new(ATTRIBUTE_WORKER, worker.to_owned())]);
		m.spawn_counter.add(1, &attrs);
	}
}

pub fn worker_dropped(worker: &str) {
	if let Some(m) = TELEMETRY.get() {
		let attrs = m.with_global_labels([KeyValue::new(ATTRIBUTE_WORKER, worker.to_owned())]);
		m.spawn_counter.add(-1, &attrs);
	}
}

/// Stable bark crate releases. Allowlisting bounds telemetry
/// cardinality since `bark_version` is client-supplied. Order does not
/// matter; matching is exact token-based (see [classify_bark_version]).
const ALLOWED_BARK_VERSIONS: &[&str] = &[
	"0.1.0", "0.1.1", "0.1.2", "0.1.3", "0.1.4",
	"0.2.0", "0.2.1", "0.2.2", "0.2.3", "0.2.4",
	"0.2.5", "0.3.0", "0.4.0", "0.5.0", "0.6.0",
	"0.6.1", "0.6.2", "0.7.0",
];

// Compile-time check: the workspace version must be in
// ALLOWED_BARK_VERSIONS so freshly-built clients count as Known.
const _: () = {
	const fn bytes_eq(a: &[u8], b: &[u8]) -> bool {
		if a.len() != b.len() {
			return false;
		}
		let mut i = 0;
		while i < a.len() {
			if a[i] != b[i] {
				return false;
			}
			i += 1;
		}
		true
	}
	const fn version_in_allowlist(ver: &str) -> bool {
		let ver = ver.as_bytes();
		let mut i = 0;
		while i < ALLOWED_BARK_VERSIONS.len() {
			if bytes_eq(ALLOWED_BARK_VERSIONS[i].as_bytes(), ver) {
				return true;
			}
			i += 1;
		}
		false
	}
	assert!(
		version_in_allowlist(server_rpc::BARK_CRATE_VERSION),
		"server_rpc::BARK_CRATE_VERSION is not in ALLOWED_BARK_VERSIONS \
		 — bump the list in server/src/telemetry.rs to include the current \
		 workspace version before releasing",
	);
};

/// Length cap on the handshake bark_version; bounds per-request scan
/// cost and log output.
const MAX_BARK_VERSION_LEN: usize = 64;

/// Classification of a client-supplied bark_version. Three variants
/// (not two) so metrics can distinguish "field missing" from "field
/// present but not recognised".
#[derive(Debug, Clone, Copy)]
pub enum BarkVersionClass {
	Missing,
	Known(&'static str),
	Unknown,
}

/// Splits decorated strings (e.g. `"bark-ffi/0.2.5-android"`) on
/// non-`[0-9.]` and matches each token exactly against
/// [ALLOWED_BARK_VERSIONS], so `"0.2.50"` does not collapse onto
/// `"0.2.5"`.
pub fn classify_bark_version(client: Option<&str>) -> BarkVersionClass {
	match client {
		None => BarkVersionClass::Missing,
		Some(v) if v.len() > MAX_BARK_VERSION_LEN => BarkVersionClass::Unknown,
		Some(v) => v.split(|c: char| !c.is_ascii_digit() && c != '.')
			.filter(|t| !t.is_empty())
			.find_map(|tok| ALLOWED_BARK_VERSIONS.iter().find(|&&a| a == tok).copied())
			.map(BarkVersionClass::Known)
			.unwrap_or(BarkVersionClass::Unknown),
	}
}

/// Buckets: one label per allowed version, plus `MISSING` (missing)
/// and `UNKNOWN` (unrecognised).
pub fn count_bark_version(class: BarkVersionClass) {
	if let Some(m) = TELEMETRY.get() {
		let bucket = match class {
			BarkVersionClass::Missing => "MISSING",
			BarkVersionClass::Known(v) => v,
			BarkVersionClass::Unknown => "UNKNOWN",
		};
		let attrs = m.with_global_labels([KeyValue::new(ATTRIBUTE_BARK_VERSION, bucket.to_string())]);
		m.bark_version_counter.add(1, &attrs);
	}
}

pub fn count_protocol_version(pver: u64) {
	if let Some(m) = TELEMETRY.get() {
		let attrs = m.with_global_labels([
			KeyValue::new(ATTRIBUTE_PROTOCOL_VERSION, Value::I64(pver as i64))
		]);
		m.protocol_version_counter.add(1, &attrs);
	}
}

pub fn set_wallet_balance(wallet_kind: WalletKind, wallet_balance: TrustedBalance) {
	if let Some(m) = TELEMETRY.get() {
		let trusted_attrs = m.with_global_labels([
			KeyValue::new(ATTRIBUTE_KIND, wallet_kind.to_string()),
			KeyValue::new(ATTRIBUTE_TYPE, "trusted"),
		]);
		m.wallet_balance_gauge.record(wallet_balance.trusted.to_sat(), &trusted_attrs);

		let untrusted_attrs = m.with_global_labels([
			KeyValue::new(ATTRIBUTE_KIND, wallet_kind.to_string()),
			KeyValue::new(ATTRIBUTE_TYPE, "untrusted"),
		]);
		m.wallet_balance_gauge.record(wallet_balance.untrusted.to_sat(), &untrusted_attrs);
	}
}

pub fn set_block_height(block_height: BlockHeight) {
	BLOCK_HEIGHT_TIP.store(block_height as u64, Ordering::Relaxed);
	if let Some(m) = TELEMETRY.get() {
		m.block_height_gauge.record(block_height as u64, m.global_labels());
	}
}

pub fn set_sync_height(block_height: BlockHeight) {
	SYNC_HEIGHT_TIP.store(block_height as u64, Ordering::Relaxed);
	if let Some(m) = TELEMETRY.get() {
		m.sync_height_gauge.record(block_height as u64, m.global_labels());
	}
}

// Initialize a new round and clear out the old data.
pub fn set_round_seq(round_seq: RoundSeq) {
	if let Some(m) = TELEMETRY.get() {
		let global_attrs = m.global_labels();
		m.round_seq_gauge.record(round_seq.inner(), global_attrs);
		m.round_attempt_gauge.record(0, global_attrs);
		m.round_input_volume_gauge.record(0, global_attrs);
		m.round_input_count_gauge.record(0, global_attrs);
		m.round_output_count_gauge.record(0, global_attrs);

		for s in RoundStep::get_all() {
			let attrs = m.with_global_labels([
				KeyValue::new(ATTRIBUTE_ROUND_STEP, s.as_str()),
			]);
			m.round_step_duration_gauge.record(0, &attrs);
		}

		for s in RoundStateKind::get_all() {
			let attrs = m.with_global_labels([
				KeyValue::new(ATTRIBUTE_STATUS, s.as_str()),
			]);
			m.round_state_gauge.record(0, &attrs);
		}
	}
}

pub fn set_round_attempt(attempt: usize) {
	if let Some(m) = TELEMETRY.get() {
		m.round_attempt_gauge.record(attempt as u64, m.global_labels());
	}
}

pub fn set_round_state(state: RoundStateKind) {
	if let Some(m) = TELEMETRY.get() {
		for s in RoundStateKind::get_all() {
			let value = if *s == state {
				1
			} else {
				0
			};

			let attrs = m.with_global_labels([
				KeyValue::new(ATTRIBUTE_STATUS, s.as_str()),
			]);
			m.round_state_gauge.record(value, &attrs);
		}
	}
}

pub fn set_round_step_duration(round_step: TimedRoundStep) {
	if let Some(m) = TELEMETRY.get() {
		let attrs = m.with_global_labels([
			KeyValue::new(ATTRIBUTE_ROUND_STEP, round_step.as_str()),
		]);
		m.round_step_duration_gauge.record(round_step.duration().as_millis() as u64, &attrs);
	}
}

pub fn set_round_metrics(
	input_volume: Amount,
	input_count: usize,
	output_count: usize,
) {
	if let Some(m) = TELEMETRY.get() {
		let global_labels = m.global_labels();
		m.round_input_volume_gauge.record(input_volume.to_sat(), global_labels);
		m.round_input_count_gauge.record(input_count as u64, global_labels);
		m.round_output_count_gauge.record(output_count as u64, global_labels);
	}
}

/// Increment the cumulative round counter and add to the cumulative volume.
///
/// Why: this lives outside [set_round_metrics] because that runs once per
/// round *attempt* (and even for empty attempts). Counting attempts inflates
/// "rounds/h" by the retry rate. Call this once per successful round.
pub fn add_round(input_volume: Amount) {
	if let Some(m) = TELEMETRY.get() {
		let global_labels = m.global_labels();
		m.round_counter.add(1, global_labels);
		m.round_volume.add(input_volume.to_sat(), global_labels);
	}
}

/// One interactive round participation by a user: existing VTXOs being
/// recycled (refreshed) into a new round. Non-interactive settlements
/// (board/LN) are excluded; those are counted by their own metrics.
///
/// `client` is the bucketed integrator name captured at SubmitPayment RPC
/// time (see `rpcserver::middleware::bucket_client`) and stashed on the
/// [`crate::round::InteractiveParticipation`] until the round finalizes.
/// We can't read `current_client()` here because emission happens on the
/// round-processing task, not on any user's RPC task.
pub fn add_refresh(input_volume_sats: u64, client: &'static str) {
	if let Some(m) = TELEMETRY.get() {
		let attrs = m.with_global_labels([KeyValue::new(RPC_CLIENT, client)]);
		m.refresh_counter.add(1, &attrs);
		m.refresh_volume.add(input_volume_sats, &attrs);
	}
}

/// One delegated round participation: the server submitted inputs into the
/// round on behalf of a user (typically an LN HTLC settlement). Volume is
/// the sum of input VTXO amounts consumed by this participation.
///
/// Delegated participations are persisted to `round_participation` before
/// the round picks them up, and we don't yet store the originating client
/// alongside them, so `client` is currently always `"delegated"` (kept
/// distinct from `"unknown"`, which specifically means "no x-user-agent
/// header on the RPC"). Add a column and thread it through if
/// per-integrator delegated attribution is wanted later.
pub fn add_delegated_participation(input_volume_sats: u64, client: &'static str) {
	if let Some(m) = TELEMETRY.get() {
		let attrs = m.with_global_labels([KeyValue::new(RPC_CLIENT, client)]);
		m.delegated_participation_counter.add(1, &attrs);
		m.delegated_participation_volume.add(input_volume_sats, &attrs);
	}
}

/// One VTXO created by a successful round, split by output policy. Padding
/// VTXOs that the server inserts to meet the tree's minimum-leaves
/// requirement are not counted.
pub fn add_round_output_pubkey(amount_sats: u64) {
	if let Some(m) = TELEMETRY.get() {
		let global_labels = m.global_labels();
		m.round_output_pubkey_counter.add(1, global_labels);
		m.round_output_pubkey_volume.add(amount_sats, global_labels);
	}
}

pub fn add_round_output_htlc_send(amount_sats: u64) {
	if let Some(m) = TELEMETRY.get() {
		let global_labels = m.global_labels();
		m.round_output_htlc_send_counter.add(1, global_labels);
		m.round_output_htlc_send_volume.add(amount_sats, global_labels);
	}
}

pub fn add_round_output_htlc_recv(amount_sats: u64) {
	if let Some(m) = TELEMETRY.get() {
		let global_labels = m.global_labels();
		m.round_output_htlc_recv_counter.add(1, global_labels);
		m.round_output_htlc_recv_volume.add(amount_sats, global_labels);
	}
}

/// A frontier VTXO's funding tx confirmed on-chain, i.e. the user (or
/// some watcher acting on their behalf) broadcast an exit-tree node. Each
/// confirmed VTXO counts as one exit; the volume is the off-chain face
/// value of the exiting VTXO.
pub fn add_unilateral_exit(amount_sats: u64) {
	if let Some(m) = TELEMETRY.get() {
		let global_labels = m.global_labels();
		m.unilateral_exit_counter.add(1, global_labels);
		m.unilateral_exit_volume.add(amount_sats, global_labels);
	}
}

pub fn set_frontier_metrics(
	claim_volume: u64,
	progress_volume: u64,
	sweep_volume: u64,
	wait_volume: u64,
) {
	if let Some(m) = TELEMETRY.get() {
		let claim_attrs = m.with_global_labels([
			KeyValue::new(ATTRIBUTE_TYPE, "claim"),
		]);
		m.frontier_gauge.record(claim_volume, &claim_attrs);

		let progress_attrs = m.with_global_labels([
			KeyValue::new(ATTRIBUTE_TYPE, "progress"),
		]);
		m.frontier_gauge.record(progress_volume, &progress_attrs);

		let sweep_attrs = m.with_global_labels([
			KeyValue::new(ATTRIBUTE_TYPE, "sweep"),
		]);
		m.frontier_gauge.record(sweep_volume, &sweep_attrs);

		let wait_attrs = m.with_global_labels([
			KeyValue::new(ATTRIBUTE_TYPE, "wait"),
		]);
		m.frontier_gauge.record(wait_volume, &wait_attrs);
	}
}

pub fn set_mailbox_put_metric(mailbox_type: MailboxType, count: usize) {
	set_mailbox_metric("put", mailbox_type, count);
}

pub fn set_mailbox_get_metric(mailbox_type: MailboxType, count: usize) {
	set_mailbox_metric("get", mailbox_type, count);
}

fn set_mailbox_metric(tp: &'static str, mailbox_type: MailboxType, count: usize) {
	if let Some(m) = TELEMETRY.get() {
		let attrs = m.with_global_labels([
			KeyValue::new(ATTRIBUTE_KIND, tp),
			KeyValue::new(ATTRIBUTE_TYPE, mailbox_type.as_str()),
		]);
		m.mailbox_counter.add(count as u64, &attrs);
	}
}

pub fn set_lightning_node_state(
	lightning_node_uri: tonic::transport::Uri,
	lightning_node_id: Option<i64>,
	pubkey: Option<PublicKey>,
	state: NodeStateKind,
) {
	let pubkey_string = match pubkey {
		Some(pubkey) => pubkey.to_string(),
		None => "".to_string(),
	};

	if let Some(m) = TELEMETRY.get() {
		for s in NodeStateKind::get_all() {
			let value = if *s == state {
				1
			} else {
				0
			};

			let attrs = m.with_global_labels([
				KeyValue::new(ATTRIBUTE_URI, lightning_node_uri.to_string()),
				KeyValue::new(ATTRIBUTE_LIGHTNING_NODE_ID, lightning_node_id.unwrap_or(0).to_string()),
				KeyValue::new(ATTRIBUTE_PUBKEY, pubkey_string.clone()),
				KeyValue::new(ATTRIBUTE_STATUS, s.as_str()),
			]);
			m.lightning_node_gauge.record(value, &attrs);
		}

		if state == NodeStateKind::Online {
			let boot_attrs = m.with_global_labels([
				KeyValue::new(ATTRIBUTE_URI, lightning_node_uri.to_string()),
				KeyValue::new(ATTRIBUTE_LIGHTNING_NODE_ID, lightning_node_id.unwrap_or(0).to_string()),
				KeyValue::new(ATTRIBUTE_PUBKEY, pubkey_string),
			]);
			m.lightning_node_boot_counter.add(1, &boot_attrs);
		}
	}
}

pub fn add_board(volume_sats: u64) {
	if let Some(m) = TELEMETRY.get() {
		let attrs = m.with_global_labels([KeyValue::new(RPC_CLIENT, current_client())]);
		m.board_counter.add(1, &attrs);
		m.board_volume.add(volume_sats, &attrs);
	}
}

pub fn add_offboard(volume_sats: u64) {
	if let Some(m) = TELEMETRY.get() {
		let attrs = m.with_global_labels([KeyValue::new(RPC_CLIENT, current_client())]);
		m.offboard_counter.add(1, &attrs);
		m.offboard_volume.add(volume_sats, &attrs);
	}
}

/// Op types for [record_ark_fee], kept typed so call sites can't drift on
/// the label string.
#[derive(Copy, Clone)]
pub enum ArkFeeOp {
	Board,
	Offboard,
	Refresh,
	LightningSend,
	LightningReceive,
}

impl ArkFeeOp {
	fn as_str(self) -> &'static str {
		match self {
			ArkFeeOp::Board => "board",
			ArkFeeOp::Offboard => "offboard",
			ArkFeeOp::Refresh => "refresh",
			ArkFeeOp::LightningSend => "lightning_send",
			ArkFeeOp::LightningReceive => "lightning_receive",
		}
	}
}

/// Record an ark-protocol fee at the success boundary of an op. Callers
/// must gate against idempotent retries so we don't double-count.
/// `round_seq` goes to the slog only, not to the counter labels, to keep
/// cardinality bounded.
pub fn record_ark_fee(op: ArkFeeOp, user_fee_sat: u64, round_seq: Option<RoundSeq>) {
	// No routing component on this path, so net == user.
	let net_fee_sat = user_fee_sat;
	// Mirror the metric in a slog so the recording path is auditable and
	// can be asserted on in integration tests. Slog fires whether or not
	// the OTel pipeline is initialised — keeping the two paths independent.
	slog!(ArkFeeRecorded,
		op_type: op.as_str().to_string(),
		net_fee_sat,
		user_fee_sat,
		routing_fee_sat: None,
		round_seq,
	);
	if let Some(m) = TELEMETRY.get() {
		let attrs = m.with_global_labels([KeyValue::new("op_type", op.as_str())]);
		m.ark_protocol_fee_sat_counter.add(net_fee_sat, &attrs);
	}
}

/// Record a lightning-send fee at Succeeded. The counter gets the net
/// margin (`user_fee - routing_fee`); the slog keeps both gross components.
/// Routing fee is a pass-through cost, not server revenue.
pub fn record_ark_fee_lightning_send(user_fee_sat: u64, routing_fee_sat: u64) {
	let net_fee_sat = user_fee_sat.saturating_sub(routing_fee_sat);
	slog!(ArkFeeRecorded,
		op_type: ArkFeeOp::LightningSend.as_str().to_string(),
		net_fee_sat,
		user_fee_sat,
		routing_fee_sat: Some(routing_fee_sat),
		round_seq: None,
	);
	if let Some(m) = TELEMETRY.get() {
		let attrs = m.with_global_labels([
			KeyValue::new("op_type", ArkFeeOp::LightningSend.as_str()),
		]);
		m.ark_protocol_fee_sat_counter.add(net_fee_sat, &attrs);
	}
}

pub fn add_arkoor_payment(volume_sats: u64) {
	if let Some(m) = TELEMETRY.get() {
		let attrs = m.with_global_labels([KeyValue::new(RPC_CLIENT, current_client())]);
		m.arkoor_payment_counter.add(1, &attrs);
		m.arkoor_payment_volume.add(volume_sats, &attrs);
	}
}

/// The `client` label is best-effort: for status transitions fired from the
/// original RPC handler (typically Requested→Submitted) it's the true
/// integrator; for transitions emitted from the background `sync_payment_attempt_status`
/// worker in `ln::cln::xpay` it degrades to `"unknown"`. Store the
/// originating client on `lightning_payment_attempt` if accurate
/// per-integrator LN attribution is wanted later.
pub fn add_lightning_payment(
	lightning_node_id: i64,
	amount_msat: u64,
	status: LightningPaymentStatus,
) {
	if let Some(m) = TELEMETRY.get() {
		let attrs = m.with_global_labels([
			KeyValue::new(ATTRIBUTE_LIGHTNING_NODE_ID, lightning_node_id.to_string()),
			KeyValue::new(ATTRIBUTE_STATUS, status.to_string()),
			KeyValue::new(RPC_CLIENT, current_client()),
		]);
		m.lightning_payment_counter.add(1, &attrs);
		m.lightning_payment_volume.add(amount_msat / 1000, &attrs);
	}
}

pub fn add_invoice_verification(lightning_node_id: i64, status: LightningPaymentStatus) {
	if let Some(m) = TELEMETRY.get() {
		let attrs = m.with_global_labels([
			KeyValue::new(ATTRIBUTE_LIGHTNING_NODE_ID, lightning_node_id.to_string()),
			KeyValue::new(ATTRIBUTE_STATUS, status.to_string()),
		]);
		m.lightning_invoice_verification_counter.add(1, &attrs);
	}
}

pub fn set_pending_invoice_verifications(lightning_node_id: i64, count: usize) {
	if let Some(m) = TELEMETRY.get() {
		let attrs = m.with_global_labels([
			KeyValue::new(ATTRIBUTE_LIGHTNING_NODE_ID, lightning_node_id.to_string()),
		]);
		m.lightning_invoice_verification_queue_gauge.record(count as u64, &attrs)
	}
}

pub fn set_open_invoices(
	lightning_node_id: i64,
	counts: &std::collections::HashMap<LightningHtlcSubscriptionStatus, usize>,
) {
	if let Some(m) = TELEMETRY.get() {
		for status in [
			LightningHtlcSubscriptionStatus::Created,
			LightningHtlcSubscriptionStatus::Accepted,
			LightningHtlcSubscriptionStatus::HtlcsReady,
		] {
			let count = counts.get(&status).copied().unwrap_or(0);
			let attrs = m.with_global_labels([
				KeyValue::new(ATTRIBUTE_LIGHTNING_NODE_ID, lightning_node_id.to_string()),
				KeyValue::new(ATTRIBUTE_STATUS, status.to_string()),
			]);
			m.lightning_open_invoices_gauge.record(count as u64, &attrs);
		}
	}
}

pub fn add_grpc_in_progress(attributes: &[KeyValue]) {
	if let Some(m) = TELEMETRY.get() {
		let attrs = m.with_global_labels(attributes.iter().cloned());
		m.grpc_request_counter.add(1, &attrs);
		m.grpc_in_progress_counter.add(1, &attrs);
	}
}

pub fn record_grpc_latency(duration: Duration, attributes: &[KeyValue]) {
	if let Some(m) = TELEMETRY.get() {
		let attrs = m.with_global_labels(attributes.iter().cloned());
		m.grpc_latency_histogram.record(duration.as_millis() as u64, &attrs);
	}
}

pub fn add_grpc_error(attributes: &[KeyValue]) {
	if let Some(m) = TELEMETRY.get() {
		let attrs = m.with_global_labels(attributes.iter().cloned());
		m.grpc_error_counter.add(1, &attrs);
	}
}

pub fn drop_grpc_in_progress(attributes: &[KeyValue]) {
	if let Some(m) = TELEMETRY.get() {
		let attrs = m.with_global_labels(attributes.iter().cloned());
		m.grpc_in_progress_counter.add(-1, &attrs);
	}
}

pub fn set_postgres_connection_pool_metrics(state: bb8::State) {
	if let Some(m) = TELEMETRY.get() {
		let connections = state.connections;
		let idle_connections = state.idle_connections;
		let global_labels = m.global_labels();
		m.postgres_connections.record(connections as u64, global_labels);
		m.postgres_idle_connections.record(idle_connections as u64, global_labels);
		let stats = state.statistics;
		m.postgres_connections_created.record(stats.connections_created, global_labels);
		m.postgres_connections_closed_broken.record(stats.connections_closed_broken, global_labels);
		m.postgres_connections_closed_idle_timeout.record(stats.connections_closed_idle_timeout, global_labels);
		m.postgres_connections_closed_invalid.record(stats.connections_closed_invalid, global_labels);
		m.postgres_connections_closed_max_lifetime.record(stats.connections_closed_max_lifetime, global_labels);
		m.postgres_get_direct.record(stats.get_direct, global_labels);
		m.postgres_get_timed_out.record(stats.get_timed_out, global_labels);
		m.postgres_get_waited.record(stats.get_waited, global_labels);
		m.postgres_get_wait_time.record(stats.get_wait_time.as_millis() as u64, global_labels);
	}
}

/// `le` boundaries for the by-expiry pool histogram, in ascending
/// blocks-until-expiry. Fine granularity across 144-250 is deliberate: 144 is
/// the default `vtxo_refresh_expiry_threshold` in `bark/src/config.rs`, so
/// this is the band where operators need to react. Anything past 288 (~48h)
/// collapses into the `+Inf` bucket. Emitted metrics are gauges shaped like a
/// Prom native histogram (see the builders in [Metrics::build]), so
/// `_bucket{le="144"}` reads directly as "past refresh threshold"; because
/// values are snapshots rather than monotonic counters, `histogram_quantile`
/// used with `rate()` will not work.
const EXPIRY_HISTOGRAM_BOUNDARIES: &[u32] = &[
	6, 72, 144, 150, 160, 170, 180, 190, 200, 225, 250, 288,
];

/// String forms for the `le` label, parallel to
/// [EXPIRY_HISTOGRAM_BOUNDARIES] plus the catch-all `+Inf` slot at the end.
const EXPIRY_HISTOGRAM_LE_LABELS: &[&str] = &[
	"6", "72", "144", "150", "160", "170", "180", "190", "200", "225", "250", "288", "+Inf",
];

const _: () = assert!(
	EXPIRY_HISTOGRAM_LE_LABELS.len() == EXPIRY_HISTOGRAM_BOUNDARIES.len() + 1,
	"expiry le-label array must have one extra entry for +Inf",
);

/// Slot count for the by-expiry histogram: one per boundary plus the `+Inf`
/// catch-all. Kept as a `const` so the working arrays live on the stack.
const EXPIRY_N_SLOTS: usize = EXPIRY_HISTOGRAM_BOUNDARIES.len() + 1;

/// `le` boundaries for the by-amount pool histogram, in ascending sats. Fixed
/// log-ish scale spanning ~1k sat to ~0.05 BTC, chosen independent of any
/// given deployment's `config.vtxo_targets` so cross-deployment dashboards
/// share the same axis. Anything past 5_000_000 sat collapses into `+Inf`.
const AMOUNT_HISTOGRAM_BOUNDARIES: &[u64] = &[
	1_000, 5_000, 10_000, 50_000, 100_000, 500_000, 1_000_000, 5_000_000,
];

/// String forms for the `le` label, parallel to
/// [AMOUNT_HISTOGRAM_BOUNDARIES] plus the catch-all `+Inf` slot at the end.
const AMOUNT_HISTOGRAM_LE_LABELS: &[&str] = &[
	"1000", "5000", "10000", "50000", "100000", "500000",
	"1000000", "5000000", "+Inf",
];

const _: () = assert!(
	AMOUNT_HISTOGRAM_LE_LABELS.len() == AMOUNT_HISTOGRAM_BOUNDARIES.len() + 1,
	"amount le-label array must have one extra entry for +Inf",
);

/// Slot count for the by-amount histogram: one per boundary plus the `+Inf`
/// catch-all. Kept as a `const` so the working arrays live on the stack.
const AMOUNT_N_SLOTS: usize = AMOUNT_HISTOGRAM_BOUNDARIES.len() + 1;

/// Snapshot of a pool aggregated for the by-expiry histogram. Extracted for
/// unit-testable computation without the OTel meter global. Fixed-size
/// arrays keep this alloc-free.
struct ExpiryHistogramSnapshot {
	/// Cumulative VTXO count per `le` boundary, plus a final `+Inf` slot.
	cum_count: [u64; EXPIRY_N_SLOTS],
	/// Cumulative VTXO sats per `le` boundary, plus a final `+Inf` slot.
	cum_sats: [u64; EXPIRY_N_SLOTS],
	/// Sum of `blocks_until_expiry` across every VTXO in the pool
	/// (matches the `_sum` of a Prom histogram observing that value).
	total_blocks: u64,
}

fn compute_expiry_histogram(
	pool: &BTreeMap<BlockHeight, BTreeMap<Amount, Vec<VtxoId>>>,
	block_height_tip: u32,
) -> ExpiryHistogramSnapshot {
	let mut per_slot_count = [0u64; EXPIRY_N_SLOTS];
	let mut per_slot_sats = [0u64; EXPIRY_N_SLOTS];
	let mut total_blocks = 0u64;

	for (&expiry_height, vtxo_map) in pool {
		let delta = expiry_height.saturating_sub(block_height_tip);
		let slot = EXPIRY_HISTOGRAM_BOUNDARIES.iter()
			.position(|&b| delta <= b)
			.unwrap_or(EXPIRY_HISTOGRAM_BOUNDARIES.len());

		for (&amount, ids) in vtxo_map {
			let n = ids.len() as u64;
			let sats = amount.to_sat().saturating_mul(n);
			per_slot_count[slot] += n;
			per_slot_sats[slot] += sats;
			total_blocks = total_blocks.saturating_add((delta as u64).saturating_mul(n));
		}
	}

	let mut cum_count = [0u64; EXPIRY_N_SLOTS];
	let mut cum_sats = [0u64; EXPIRY_N_SLOTS];
	let (mut running_count, mut running_sats) = (0u64, 0u64);
	for i in 0..EXPIRY_N_SLOTS {
		running_count += per_slot_count[i];
		running_sats += per_slot_sats[i];
		cum_count[i] = running_count;
		cum_sats[i] = running_sats;
	}

	ExpiryHistogramSnapshot { cum_count, cum_sats, total_blocks }
}

pub fn set_vtxo_pool_metrics(
	pool: &BTreeMap<BlockHeight, BTreeMap<Amount, Vec<VtxoId>>>,
) {
	let Some(m) = TELEMETRY.get() else { return };

	let block_height_tip = BLOCK_HEIGHT_TIP.load(Ordering::Relaxed) as u32;
	let global = m.global_labels();

	let hist = compute_expiry_histogram(pool, block_height_tip);
	for (i, &le_label) in EXPIRY_HISTOGRAM_LE_LABELS.iter().enumerate() {
		let attrs = m.with_global_labels([KeyValue::new("le", le_label)]);
		m.vtxo_pool_expiry_blocks_bucket_gauge.record(hist.cum_count[i], &attrs);
		m.vtxo_pool_expiry_sats_bucket_gauge.record(hist.cum_sats[i], &attrs);
	}
	let total_count = hist.cum_count[EXPIRY_N_SLOTS - 1];
	let total_sats = hist.cum_sats[EXPIRY_N_SLOTS - 1];
	m.vtxo_pool_expiry_blocks_count_gauge.record(total_count, global);
	m.vtxo_pool_expiry_blocks_sum_gauge.record(hist.total_blocks, global);
	m.vtxo_pool_expiry_sats_count_gauge.record(total_count, global);
	m.vtxo_pool_expiry_sats_sum_gauge.record(total_sats, global);

	let amt = compute_amount_histogram(pool);
	for (i, &le_label) in AMOUNT_HISTOGRAM_LE_LABELS.iter().enumerate() {
		let attrs = m.with_global_labels([KeyValue::new("le", le_label)]);
		m.vtxo_pool_amount_bucket_gauge.record(amt.cum_count[i], &attrs);
		m.vtxo_pool_amount_sats_bucket_gauge.record(amt.cum_sats[i], &attrs);
	}
	m.vtxo_pool_amount_count_gauge.record(amt.cum_count[AMOUNT_N_SLOTS - 1], global);
	m.vtxo_pool_amount_sum_gauge.record(amt.cum_sats[AMOUNT_N_SLOTS - 1], global);
}

/// Snapshot of a pool aggregated for the by-amount histogram. Same shape as
/// [ExpiryHistogramSnapshot] but the axis is amount, not blocks-until-expiry.
/// Fixed-size arrays because the boundaries are compile-time constants.
struct AmountHistogramSnapshot {
	/// Cumulative VTXO count per `le` boundary, plus a final `+Inf` slot.
	cum_count: [u64; AMOUNT_N_SLOTS],
	/// Cumulative sats in VTXOs at or under each `le` boundary,
	/// plus a final `+Inf` slot.
	cum_sats: [u64; AMOUNT_N_SLOTS],
}

fn compute_amount_histogram(
	pool: &BTreeMap<BlockHeight, BTreeMap<Amount, Vec<VtxoId>>>,
) -> AmountHistogramSnapshot {
	let mut per_slot_count = [0u64; AMOUNT_N_SLOTS];
	let mut per_slot_sats = [0u64; AMOUNT_N_SLOTS];

	for vtxo_map in pool.values() {
		for (&amount, ids) in vtxo_map {
			let n = ids.len() as u64;
			let sats_per_vtxo = amount.to_sat();
			let sats = sats_per_vtxo.saturating_mul(n);
			let slot = AMOUNT_HISTOGRAM_BOUNDARIES.iter()
				.position(|&b| sats_per_vtxo <= b)
				.unwrap_or(AMOUNT_HISTOGRAM_BOUNDARIES.len());
			per_slot_count[slot] += n;
			per_slot_sats[slot] += sats;
		}
	}

	let mut cum_count = [0u64; AMOUNT_N_SLOTS];
	let mut cum_sats = [0u64; AMOUNT_N_SLOTS];
	let (mut running_count, mut running_sats) = (0u64, 0u64);
	for i in 0..AMOUNT_N_SLOTS {
		running_count += per_slot_count[i];
		running_sats += per_slot_sats[i];
		cum_count[i] = running_count;
		cum_sats[i] = running_sats;
	}

	AmountHistogramSnapshot { cum_count, cum_sats }
}

pub fn set_fee_estimator_metrics(
	fast_sat_vb: f64,
	regular_sat_vb: f64,
	slow_sat_vb: f64,
	using_fallback: bool,
) {
	if let Some(m) = TELEMETRY.get() {
		let global_labels = m.global_labels();
		let fast_labels = m.with_global_labels([KeyValue::new("estimator", "fast")]);
		let regular_labels = m.with_global_labels([KeyValue::new("estimator", "regular")]);
		let slow_labels = m.with_global_labels([KeyValue::new("estimator", "slow")]);
		m.fee_rate_gauge.record(fast_sat_vb, &fast_labels);
		m.fee_rate_gauge.record(regular_sat_vb, &regular_labels);
		m.fee_rate_gauge.record(slow_sat_vb, &slow_labels);
		m.fee_rate_using_fallback_gauge.record(if using_fallback { 1 } else { 0 }, global_labels);
	}
}

pub fn record_tokio_runtime_delay(actual_ms: u64) {
	if let Some(m) = TELEMETRY.get() {
		m.tokio_runtime_delay_histogram.record(actual_ms, m.global_labels());
	}
}

/// An extention trait for span tracing.
pub trait SpanExt {
	/// internal method used by provided methods
	fn _set_attribute(&mut self, attribute: KeyValue);

	fn set_int_attr(&mut self, key: impl Into<Key>, int: impl TryInto<i64>) {
		self._set_attribute(KeyValue::new(key, Value::I64(int.try_into().unwrap_or(-1))));
	}

	fn set_str_attr(&mut self, key: impl Into<Key>, value: impl fmt::Display) {
		self._set_attribute(KeyValue::new(key, Value::String(value.to_string().into())));
	}

	/// Sets a byte array attribute as a hexadecimal string.
	fn set_bytes_attr(&mut self, key: impl Into<Key>, bytes: &[u8]) {
		self._set_attribute(KeyValue::new(key, Value::String(bytes.as_hex().to_string().into())));
	}
}

impl SpanExt for BoxedSpan {
	fn _set_attribute(&mut self, attribute: KeyValue) {
	    self.set_attribute(attribute);
	}
}

impl<'a> SpanExt for SpanRef<'a> {
	fn _set_attribute(&mut self, attribute: KeyValue) {
	    self.set_attribute(attribute);
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn known(class: BarkVersionClass) -> Option<&'static str> {
		match class {
			BarkVersionClass::Known(v) => Some(v),
			_ => None,
		}
	}

	#[test]
	fn classify_bark_version_missing() {
		assert!(matches!(classify_bark_version(None), BarkVersionClass::Missing));
	}

	#[test]
	fn classify_bark_version_exact() {
		assert_eq!(known(classify_bark_version(Some("0.2.5"))), Some("0.2.5"));
	}

	#[test]
	fn classify_bark_version_decorated() {
		assert_eq!(
			known(classify_bark_version(Some("bark-ffi/0.2.5-android"))),
			Some("0.2.5"),
		);
	}

	#[test]
	fn classify_bark_version_no_substring_bleed() {
		// 0.2.50 must not contains-match 0.2.5.
		assert!(matches!(
			classify_bark_version(Some("0.2.50")),
			BarkVersionClass::Unknown,
		));
		assert!(matches!(
			classify_bark_version(Some("bark-ffi/0.2.50-android")),
			BarkVersionClass::Unknown,
		));
	}

	#[test]
	fn classify_bark_version_unknown_and_junk() {
		assert!(matches!(classify_bark_version(Some("")), BarkVersionClass::Unknown));
		assert!(matches!(classify_bark_version(Some("9.9.9")), BarkVersionClass::Unknown));
		assert!(matches!(classify_bark_version(Some("garbage")), BarkVersionClass::Unknown));
	}

	#[test]
	fn classify_bark_version_over_length() {
		let long = "a".repeat(MAX_BARK_VERSION_LEN + 1);
		assert!(matches!(
			classify_bark_version(Some(&long)),
			BarkVersionClass::Unknown,
		));
	}

	fn dummy_vtxo_id(seed: u8) -> VtxoId {
		VtxoId::from_slice(&[seed; 36]).expect("36-byte slice")
	}

	fn build_pool(entries: &[(BlockHeight, u64, usize)])
		-> BTreeMap<BlockHeight, BTreeMap<Amount, Vec<VtxoId>>>
	{
		let mut pool = BTreeMap::new();
		for (i, &(expiry, sats, n)) in entries.iter().enumerate() {
			let amount = Amount::from_sat(sats);
			let ids = (0..n).map(|k| dummy_vtxo_id(i as u8 + k as u8)).collect();
			pool.entry(expiry).or_insert_with(BTreeMap::new).insert(amount, ids);
		}
		pool
	}

	#[test]
	fn expiry_histogram_empty_pool_is_all_zero() {
		let pool = BTreeMap::new();
		let hist = compute_expiry_histogram(&pool, 800_000);
		assert_eq!(hist.cum_count.last().copied().unwrap(), 0, "count is 0");
		assert_eq!(hist.cum_sats.last().copied().unwrap(), 0, "sats is 0");
		assert_eq!(hist.total_blocks, 0);
		assert!(hist.cum_count.iter().all(|&x| x == 0));
		assert!(hist.cum_sats.iter().all(|&x| x == 0));
	}

	#[test]
	fn expiry_histogram_buckets_are_cumulative_and_ordered() {
		// One VTXO in each ascending bucket, plus a couple past +Inf.
		let tip: BlockHeight = 800_000;
		let entries: Vec<(BlockHeight, u64, usize)> = vec![
			(tip + 3,   100, 1),   // le=6:   1 VTXO,     100 sat
			(tip + 40,  200, 1),   // le=72:  1 VTXO,     200 sat
			(tip + 140, 300, 1),   // le=144: 1 VTXO,     300 sat
			(tip + 148, 400, 1),   // le=150: 1 VTXO,     400 sat
			(tip + 260, 500, 1),   // le=288: 1 VTXO,     500 sat
			(tip + 1000, 999, 2),  // le=+Inf: 2 VTXOs,   999+999 = 1998 sat
		];
		let pool = build_pool(&entries);
		let hist = compute_expiry_histogram(&pool, tip);

		let last = *hist.cum_count.last().unwrap();
		assert_eq!(last, 7, "total VTXO count");
		assert_eq!(*hist.cum_sats.last().unwrap(), 100 + 200 + 300 + 400 + 500 + 1998);

		for i in 1..hist.cum_count.len() {
			assert!(hist.cum_count[i-1] <= hist.cum_count[i], "count monotonic at le index {i}");
			assert!(hist.cum_sats[i-1] <= hist.cum_sats[i], "sats monotonic at le index {i}");
		}

		// Threshold read: `_bucket{le="144"}` counts VTXOs at or under 144 blocks left.
		let ix_144 = EXPIRY_HISTOGRAM_LE_LABELS.iter().position(|&l| l == "144").unwrap();
		assert_eq!(hist.cum_count[ix_144], 3, "3 VTXOs are past the wallet refresh threshold");
		assert_eq!(hist.cum_sats[ix_144], 100 + 200 + 300);
	}

	#[test]
	fn expiry_histogram_exactly_at_boundary_lands_in_that_bucket() {
		let tip: BlockHeight = 800_000;
		let pool = build_pool(&[(tip + 144, 1000, 1)]);
		let hist = compute_expiry_histogram(&pool, tip);

		let ix_143_or_prev = EXPIRY_HISTOGRAM_LE_LABELS.iter().position(|&l| l == "72").unwrap();
		let ix_144 = EXPIRY_HISTOGRAM_LE_LABELS.iter().position(|&l| l == "144").unwrap();
		assert_eq!(hist.cum_count[ix_143_or_prev], 0, "not in the le=72 bucket");
		assert_eq!(hist.cum_count[ix_144], 1, "delta=144 lands in le=144, not le=150");
	}

	#[test]
	fn expiry_histogram_past_tip_saturates_to_zero_delta() {
		// A VTXO whose expiry is already behind the current tip.
		let tip: BlockHeight = 800_000;
		let pool = build_pool(&[(tip - 5, 42, 1)]);
		let hist = compute_expiry_histogram(&pool, tip);
		// delta saturates to 0, which is <= 6, so it lands in the first bucket.
		let ix_6 = 0;
		assert_eq!(hist.cum_count[ix_6], 1);
		assert_eq!(hist.cum_sats[ix_6], 42);
		assert_eq!(hist.total_blocks, 0, "saturated delta contributes 0 to sum");
	}

	#[test]
	fn expiry_histogram_sum_of_blocks_weighted_by_count() {
		let tip: BlockHeight = 800_000;
		let pool = build_pool(&[
			(tip + 10, 100, 3),  // 10 blocks * 3 VTXOs = 30
			(tip + 50, 200, 2),  // 50 blocks * 2 VTXOs = 100
		]);
		let hist = compute_expiry_histogram(&pool, tip);
		assert_eq!(hist.total_blocks, 30 + 100);
	}

	#[test]
	fn amount_histogram_buckets_are_cumulative() {
		// AMOUNT_HISTOGRAM_BOUNDARIES = [1k, 5k, 10k, 50k, 100k, 500k, 1M, 5M] + Inf.
		let tip: BlockHeight = 800_000;
		let pool = build_pool(&[
			(tip + 100, 500,       2),   // dust: 2 VTXOs, 500 sat each,     le=1000
			(tip + 100, 5_000,     1),   // 1 VTXO, 5000 sat,                 le=5000
			(tip + 100, 50_000,    1),   // 1 VTXO, 50k sat,                  le=50000
			(tip + 100, 5_000_000, 1),   // 1 VTXO, 5M sat,                   le=5000000
			(tip + 100, 9_999_999, 1),   // 1 VTXO, ~0.1 BTC,                 le=+Inf
		]);
		let hist = compute_amount_histogram(&pool);

		// Slot indices parallel to AMOUNT_HISTOGRAM_LE_LABELS.
		let le_of = |label: &str| -> usize {
			AMOUNT_HISTOGRAM_LE_LABELS.iter().position(|&l| l == label).unwrap()
		};
		assert_eq!(hist.cum_count[le_of("1000")], 2);
		assert_eq!(hist.cum_count[le_of("5000")], 3);
		assert_eq!(hist.cum_count[le_of("50000")], 4);
		assert_eq!(hist.cum_count[le_of("5000000")], 5);
		assert_eq!(hist.cum_count[le_of("+Inf")], 6);

		assert_eq!(hist.cum_sats[le_of("1000")], 1_000);
		assert_eq!(hist.cum_sats[le_of("5000")], 6_000);
		assert_eq!(hist.cum_sats[le_of("50000")], 56_000);
		assert_eq!(hist.cum_sats[le_of("5000000")], 5_056_000);
		assert_eq!(hist.cum_sats[le_of("+Inf")], 5_056_000 + 9_999_999);

		for i in 1..hist.cum_count.len() {
			assert!(hist.cum_count[i-1] <= hist.cum_count[i]);
			assert!(hist.cum_sats[i-1] <= hist.cum_sats[i]);
		}
	}

	#[test]
	fn amount_histogram_boundary_lands_in_that_bucket() {
		// A VTXO with amount exactly 1000 must land in le=1000, not le=5000.
		let tip: BlockHeight = 800_000;
		let pool = build_pool(&[(tip + 100, 1_000, 1)]);
		let hist = compute_amount_histogram(&pool);
		let ix_1000 = AMOUNT_HISTOGRAM_LE_LABELS.iter().position(|&l| l == "1000").unwrap();
		let ix_5000 = AMOUNT_HISTOGRAM_LE_LABELS.iter().position(|&l| l == "5000").unwrap();
		assert_eq!(hist.cum_count[ix_1000], 1);
		assert_eq!(hist.cum_count[ix_5000], 1, "no jump above the landing bucket");
		assert_eq!(hist.cum_sats[ix_1000], 1_000);
	}

	#[test]
	fn amount_histogram_empty_pool() {
		let pool = BTreeMap::new();
		let hist = compute_amount_histogram(&pool);
		assert!(hist.cum_count.iter().all(|&x| x == 0));
		assert!(hist.cum_sats.iter().all(|&x| x == 0));
	}

	#[test]
	fn amount_histogram_dust_below_smallest_boundary_still_lands_in_first_slot() {
		// A VTXO smaller than any boundary lands in the first (le=1000) slot.
		let tip: BlockHeight = 800_000;
		let pool = build_pool(&[(tip + 100, 42, 1)]);
		let hist = compute_amount_histogram(&pool);
		assert_eq!(hist.cum_count[0], 1);
		assert_eq!(hist.cum_sats[0], 42);
	}

	#[test]
	fn ark_fee_op_labels_are_stable() {
		// These strings are emitted as Prometheus label values; renaming
		// them would silently break existing dashboards / alerts.
		assert_eq!(ArkFeeOp::Board.as_str(),            "board");
		assert_eq!(ArkFeeOp::Offboard.as_str(),         "offboard");
		assert_eq!(ArkFeeOp::Refresh.as_str(),          "refresh");
		assert_eq!(ArkFeeOp::LightningSend.as_str(),    "lightning_send");
		assert_eq!(ArkFeeOp::LightningReceive.as_str(), "lightning_receive");
	}
}
