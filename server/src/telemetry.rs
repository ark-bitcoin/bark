use std::cmp::PartialEq;
use std::collections::BTreeMap;
use std::{cmp, fmt};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use smallvec::SmallVec;
use ark::rounds::RoundSeq;
use bdk_wallet::Balance;
use bitcoin::secp256k1::PublicKey;
use bitcoin::{Amount, Network};
use bitcoin::hex::DisplayHex;
use bitcoin_ext::BlockHeight;
use opentelemetry::global::BoxedSpan;
use opentelemetry::metrics::{Counter, Gauge, Histogram, UpDownCounter};
use opentelemetry::{Key, Value};
use opentelemetry::{global, KeyValue};
use opentelemetry::trace::{Span, SpanRef, TracerProvider};
use opentelemetry_otlp::{Compression, WithExportConfig, WithTonicConfig};
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::trace::{RandomIdGenerator, Sampler};
use tokio::sync::OnceCell;
use tokio::time::Instant;
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{EnvFilter, Registry};
use ark::VtxoId;
use crate::database::ln::LightningPaymentStatus;
use crate::ln::cln::ClnNodeStateKind;
use crate::round::RoundStateKind;
use crate::wallet::WalletKind;

pub const TRACE_RUN_ROUND: &str = "round";
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
}

/// [MetricsService] for captaind
pub struct Captaind;

impl MetricsService for Captaind {
	const NAME: &'static str = "captaind";
	const TRACER: &'static str = "captaind";
	const METER: &'static str = "captaind";
}

/// [MetricsService] for watchmand
pub struct Watchmand;

impl MetricsService for Watchmand {
	const NAME: &'static str = "watchmand";
	const TRACER: &'static str = "watchmand";
	const METER: &'static str = "watchmand";
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum RoundStep {
	AttemptInitiation,
	ReceivePayments,
	ConstructVtxoTree,
	SendingVtxoProposal,
	ReceiveVtxoSignatures,
	ConstructRoundProposal,
	CombineVtxoSignatures,
	ReceiveForfeitSignatures,
	FinalStage,
	SignOnChainTransaction,
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

	// When changing this also change `get_all`

	pub fn as_str(&self) -> &'static str {
		match self {
			RoundStep::AttemptInitiation => "round_attempt",
			RoundStep::ReceivePayments => "round_receive_payments",
			RoundStep::SendingVtxoProposal => "round_sending_vtxo_proposal",
			RoundStep::ReceiveVtxoSignatures => "round_receive_vtxo_signatures",
			RoundStep::CombineVtxoSignatures => "round_combine_vtxo_signatures",
			RoundStep::ConstructVtxoTree => "round_construct_vtxo_tree",
			RoundStep::ConstructRoundProposal => "round_construct_round_proposal",
			RoundStep::ReceiveForfeitSignatures => "round_receive_forfeit_signatures",
			RoundStep::SignOnChainTransaction => "round_sign_on_chain_transaction",
			RoundStep::FinalStage => "round_finalize_stage",
			RoundStep::Persist => "round_persist",
		}
	}

	pub fn get_all() -> &'static [RoundStep] {
		&[
			RoundStep::AttemptInitiation,
			RoundStep::ReceivePayments,
			RoundStep::SendingVtxoProposal,
			RoundStep::ReceiveVtxoSignatures,
			RoundStep::CombineVtxoSignatures,
			RoundStep::ConstructVtxoTree,
			RoundStep::ConstructRoundProposal,
			RoundStep::ReceiveForfeitSignatures,
			RoundStep::SignOnChainTransaction,
			RoundStep::FinalStage,
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
/// The [numeric status code](https://github.com/grpc/grpc/blob/v1.33.2/doc/statuscodes.md)
/// of the gRPC request.
pub const RPC_GRPC_STATUS_CODE: &str = opentelemetry_semantic_conventions::attribute::RPC_GRPC_STATUS_CODE;

/// The global open-telemetry context to register metrics.
static TELEMETRY: OnceCell<Metrics> = OnceCell::const_new();
static BLOCK_HEIGHT_TIP: AtomicU64 = AtomicU64::new(0);

/// Initialize open-telemetry.
///
/// MUST be called (only once) before registering or updating metrics.
pub fn init_telemetry<S: MetricsService>(
	endpoint: &str,
	otel_tracing_sampler: Option<f64>,
	otel_deployment_name: &str,
	network: Network,
	round_interval: Duration,
	max_vtxo_amount: Option<Amount>,
	server_pubkey: PublicKey,
) {
	TELEMETRY.set(Metrics::init::<S>(
		endpoint,
		otel_tracing_sampler,
		otel_deployment_name,
		network,
		round_interval,
		max_vtxo_amount,
		server_pubkey,
	)).expect("Telemetry already initialized");
}

#[derive(Debug)]
struct Metrics {
	spawn_counter: UpDownCounter<i64>,
	bark_version_counter: Counter<u64>,
	protocol_version_counter: Counter<u64>,
	wallet_balance_gauge: Gauge<u64>,
	block_height_gauge: Gauge<u64>,
	round_seq_gauge: Gauge<u64>,
	round_state_gauge: Gauge<u64>,
	round_step_duration_gauge: Gauge<u64>,
	round_attempt_gauge: Gauge<u64>,
	round_input_volume_gauge: Gauge<u64>,
	round_input_count_gauge: Gauge<u64>,
	round_output_count_gauge: Gauge<u64>,
	round_offboard_count_gauge: Gauge<u64>,
	pending_expired_operation_gauge: Gauge<u64>,
	pending_sweeper_gauge: Gauge<u64>,
	pending_forfeit_gauge: Gauge<u64>,
	mailbox_counter: Counter<u64>,
	lightning_node_gauge: Gauge<u64>,
	lightning_node_boot_counter: Counter<u64>,
	lightning_payment_counter: Counter<u64>,
	lightning_payment_volume: Counter<u64>,
	lightning_invoice_verification_counter: Counter<u64>,
	lightning_invoice_verification_queue_gauge: Gauge<u64>,
	lightning_open_invoices_gauge: Gauge<u64>,
	vtxo_pool_amount_gauge: Gauge<u64>,
	vtxo_pool_amount_max_gauge: Gauge<u64>,
	vtxo_pool_count_gauge: Gauge<u64>,
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
	global_labels: Vec<KeyValue>,
}

impl Metrics {
	fn init<S: MetricsService>(
		endpoint: &str,
		otel_tracing_sampler: Option<f64>,
		otel_deployment_name: &str,
		network: Network,
		round_interval: Duration,
		max_vtxo_amount: Option<Amount>,
		server_pubkey: PublicKey,
	) -> Self {
		global::set_text_map_propagator(TraceContextPropagator::new());

		let trace_exporter = opentelemetry_otlp::SpanExporter::builder()
			.with_tonic()
			.with_endpoint(endpoint)
			.with_timeout(Duration::from_secs(10))
			.with_compression(Compression::Gzip)
			.build().unwrap();

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
			.unwrap_or(Sampler::AlwaysOff);

		let tracer_provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
			.with_batch_exporter(trace_exporter)
			.with_sampler(tracer_sampler)
			.with_id_generator(RandomIdGenerator::default())
			.with_max_events_per_span(64)
			.with_max_attributes_per_span(16)
			.with_resource(resource.clone())
			.build();

		let captaind_tracer = tracer_provider.tracer(S::TRACER);

		global::set_tracer_provider(tracer_provider);

		// Set up the tracing subscriber
		let filter = EnvFilter::from_default_env()
			.add_directive("h2=off".parse().unwrap());
		let captaind_telemetry = OpenTelemetryLayer::new(captaind_tracer);
		let subscriber = Registry::default()
			.with(filter)
			.with(captaind_telemetry);
		tracing::subscriber::set_global_default(subscriber)
			.map_err(|err| anyhow::anyhow!("Failed to set tracing subscriber: {:?}", err)).unwrap();

		let metrics_exporter = opentelemetry_otlp::MetricExporter::builder()
			// Build exporter using Delta Temporality (Defaults to Temporality::Cumulative)
			// .with_temporality(opentelemetry_sdk::metrics::Temporality::Delta)
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

		let meter = global::meter_provider().meter(S::METER);
		let spawn_counter = meter.i64_up_down_counter("spawn_counter").build();
		let bark_version_counter = meter.u64_counter("bark_version_counter").build();
		let protocol_version_counter = meter.u64_counter("protocol_version_counter").build();
		let wallet_balance_gauge = meter.u64_gauge("wallet_balance_gauge").build();
		let block_height_gauge = meter.u64_gauge("block_gauge").build();
		let round_seq_gauge = meter.u64_gauge("round_seq_gauge").build();
		let round_state_gauge = meter.u64_gauge("round_state_gauge").build();
		let round_step_duration_gauge = meter.u64_gauge("round_step_duration_gauge").build();
		let round_attempt_gauge = meter.u64_gauge("round_attempt_gauge").build();
		let round_input_volume_gauge = meter.u64_gauge("round_input_volume_gauge").build();
		let round_input_count_gauge = meter.u64_gauge("round_input_count_gauge").build();
		let round_output_count_gauge = meter.u64_gauge("round_output_count_gauge").build();
		let round_offboard_count_gauge = meter.u64_gauge("round_offboard_count_gauge").build();
		let pending_expired_operation_gauge = meter.u64_gauge("pending_expired_operation_gauge").build();
		let pending_sweeper_gauge = meter.u64_gauge("pending_sweeper_gauge").build();
		let mailbox_counter = meter.u64_counter("mailbox_counter").build();
		let pending_forfeit_gauge = meter.u64_gauge("pending_forfeit_gauge").build();
		let lightning_node_gauge = meter.u64_gauge("lightning_node_gauge").build();
		let lightning_node_boot_counter = meter.u64_counter("lightning_node_boot_counter").build();
		let lightning_payment_counter = meter.u64_counter("lightning_payment_counter").build();
		let lightning_payment_volume = meter.u64_counter("lightning_payment_volume").build();
		let lightning_invoice_verification_counter = meter.u64_counter("lightning_invoice_verification_counter").build();
		let lightning_invoice_verification_queue_gauge = meter.u64_gauge("lightning_invoice_verification_queue_gauge").build();
		let lightning_open_invoices_gauge = meter.u64_gauge("lightning_open_invoices_gauge").build();
		let vtxo_pool_amount_gauge = meter.u64_gauge("vtxo_pool_amount_gauge").build();
		let vtxo_pool_amount_max_gauge = meter.u64_gauge("vtxo_pool_amount_max_gauge").build();
		let vtxo_pool_count_gauge = meter.u64_gauge("vtxo_pool_count_gauge").build();
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
			round_seq_gauge,
			round_state_gauge,
			round_step_duration_gauge,
			round_attempt_gauge,
			round_input_volume_gauge,
			round_input_count_gauge,
			round_output_count_gauge,
			round_offboard_count_gauge,
			pending_expired_operation_gauge,
			pending_sweeper_gauge,
			pending_forfeit_gauge,
			mailbox_counter,
			lightning_node_gauge,
			lightning_node_boot_counter,
			lightning_payment_counter,
			lightning_payment_volume,
			lightning_invoice_verification_counter,
			lightning_invoice_verification_queue_gauge,
			lightning_open_invoices_gauge,
			vtxo_pool_amount_gauge,
			vtxo_pool_amount_max_gauge,
			vtxo_pool_count_gauge,
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
			log::warn!(
				"Telemetry attributes exceeded stack allocation limit: {} attributes will cause heap allocation",
				attrs.len()
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

pub fn count_bark_version(client: Option<String>) {
	if let Some(m) = TELEMETRY.get() {
		let client = client.unwrap_or_else(|| "UNKNOWN".to_string());
		let attrs = m.with_global_labels([KeyValue::new(ATTRIBUTE_BARK_VERSION, client)]);
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

pub fn set_wallet_balance(wallet_kind: WalletKind, wallet_balance: Balance) {
	if let Some(m) = TELEMETRY.get() {
		let confirmed_attrs = m.with_global_labels([
			KeyValue::new(ATTRIBUTE_KIND, wallet_kind.to_string()),
			KeyValue::new(ATTRIBUTE_TYPE, "confirmed"),
		]);
		m.wallet_balance_gauge.record(wallet_balance.confirmed.to_sat(), &confirmed_attrs);

		let immature_attrs = m.with_global_labels([
			KeyValue::new(ATTRIBUTE_KIND, wallet_kind.to_string()),
			KeyValue::new(ATTRIBUTE_TYPE, "immature"),
		]);
		m.wallet_balance_gauge.record(wallet_balance.immature.to_sat(), &immature_attrs);

		let trusted_attrs = m.with_global_labels([
			KeyValue::new(ATTRIBUTE_KIND, wallet_kind.to_string()),
			KeyValue::new(ATTRIBUTE_TYPE, "trusted_pending"),
		]);
		m.wallet_balance_gauge.record(wallet_balance.trusted_pending.to_sat(), &trusted_attrs);

		let untrusted_attrs = m.with_global_labels([
			KeyValue::new(ATTRIBUTE_KIND, wallet_kind.to_string()),
			KeyValue::new(ATTRIBUTE_TYPE, "untrusted_pending"),
		]);
		m.wallet_balance_gauge.record(wallet_balance.untrusted_pending.to_sat(), &untrusted_attrs);
	}
}

pub fn set_block_height(block_height: BlockHeight) {
	BLOCK_HEIGHT_TIP.store(block_height as u64, Ordering::Relaxed);
	if let Some(m) = TELEMETRY.get() {
		m.block_height_gauge.record(block_height as u64, m.global_labels());
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
		m.round_offboard_count_gauge.record(0, global_attrs);

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
	offboard_count: usize,
) {
	if let Some(m) = TELEMETRY.get() {
		let global_labels = m.global_labels();
		m.round_input_volume_gauge.record(input_volume.to_sat(), global_labels);
		m.round_input_count_gauge.record(input_count as u64, global_labels);
		m.round_output_count_gauge.record(output_count as u64, global_labels);
		m.round_offboard_count_gauge.record(offboard_count as u64, global_labels);
	}
}

pub fn set_pending_expired_rounds_count(pending_expired_rounds_count: usize) {
	if let Some(m) = TELEMETRY.get() {
		let attrs = m.with_global_labels([
			KeyValue::new(ATTRIBUTE_TYPE, "rounds"),
		]);
		m.pending_expired_operation_gauge.record(pending_expired_rounds_count as u64, &attrs);
	}
}

pub fn set_pending_expired_boards_count(pending_expired_boards_count: usize) {
	if let Some(m) = TELEMETRY.get() {
		let attrs = m.with_global_labels([
			KeyValue::new(ATTRIBUTE_TYPE, "boards"),
		]);
		m.pending_expired_operation_gauge.record(pending_expired_boards_count as u64, &attrs);
	}
}

pub fn set_pending_sweeper_stats(
	pending_tx_count: usize,
	pending_tx_volume: u64,
	pending_utxo_count: usize,
) {
	if let Some(m) = TELEMETRY.get() {
		let tx_attrs = m.with_global_labels([
			KeyValue::new(ATTRIBUTE_TYPE, "transaction_count"),
		]);
		m.pending_sweeper_gauge.record(pending_tx_count as u64, &tx_attrs);

		let volume_attrs = m.with_global_labels([
			KeyValue::new(ATTRIBUTE_TYPE, "transaction_volume"),
		]);
		m.pending_sweeper_gauge.record(pending_tx_volume, &volume_attrs);

		let utxo_attrs = m.with_global_labels([
			KeyValue::new(ATTRIBUTE_TYPE, "utxo_count"),
		]);
		m.pending_sweeper_gauge.record(pending_utxo_count as u64, &utxo_attrs);
	}
}

pub fn set_forfeit_metrics(
	pending_exit_tx_count: usize,
	pending_exit_volume: u64,
	pending_claim_count: usize,
	pending_claim_volume: u64,
) {
	if let Some(ref m) = TELEMETRY.get() {
		let exit_tx_attrs = m.with_global_labels([
			KeyValue::new(ATTRIBUTE_TYPE, "pending_exit_transaction_count"),
		]);
		m.pending_forfeit_gauge.record(pending_exit_tx_count as u64, &exit_tx_attrs);

		let exit_volume_attrs = m.with_global_labels([
			KeyValue::new(ATTRIBUTE_TYPE, "pending_exit_transaction_volume"),
		]);
		m.pending_forfeit_gauge.record(pending_exit_volume as u64, &exit_volume_attrs);

		let claim_count_attrs = m.with_global_labels([
			KeyValue::new(ATTRIBUTE_TYPE, "pending_claim_count"),
		]);
		m.pending_forfeit_gauge.record(pending_claim_count as u64, &claim_count_attrs);

		let claim_volume_attrs = m.with_global_labels([
			KeyValue::new(ATTRIBUTE_TYPE, "pending_claim_volume"),
		]);
		m.pending_forfeit_gauge.record(pending_claim_volume as u64, &claim_volume_attrs)
	}
}

#[derive(Debug)]
pub enum MailboxType {
	LegacyVtxo,
	BlindedVtxo,
}

impl MailboxType {
	pub fn to_string(&self) -> String {
		match self {
			MailboxType::LegacyVtxo => "legacy_vtxo".to_owned(),
			MailboxType::BlindedVtxo => "blinded_vtxo".to_owned(),
		}
	}
}

pub fn add_to_mailbox(mailbox_type: MailboxType, count: usize) {
	set_mailbox_metric(mailbox_type, "add", count);
}

pub fn get_from_mailbox(mailbox_type: MailboxType, count: usize) {
	set_mailbox_metric(mailbox_type, "get", count);
}

fn set_mailbox_metric(mailbox_type: MailboxType, t: &'static str, count: usize) {
	if let Some(m) = TELEMETRY.get() {
		let attrs = m.with_global_labels([
			KeyValue::new(ATTRIBUTE_KIND, mailbox_type.to_string()),
			KeyValue::new(ATTRIBUTE_TYPE, t),
		]);
		m.mailbox_counter.add(count as u64, &attrs);
	}
}

pub fn set_lightning_node_state(
	lightning_node_uri: tonic::transport::Uri,
	lightning_node_id: Option<i64>,
	pubkey: Option<PublicKey>,
	state: ClnNodeStateKind,
) {
	let pubkey_string = match pubkey {
		Some(pubkey) => pubkey.to_string(),
		None => "".to_string(),
	};

	if let Some(m) = TELEMETRY.get() {
		for s in ClnNodeStateKind::get_all() {
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

		if state == ClnNodeStateKind::Online {
			let boot_attrs = m.with_global_labels([
				KeyValue::new(ATTRIBUTE_URI, lightning_node_uri.to_string()),
				KeyValue::new(ATTRIBUTE_LIGHTNING_NODE_ID, lightning_node_id.unwrap_or(0).to_string()),
				KeyValue::new(ATTRIBUTE_PUBKEY, pubkey_string),
			]);
			m.lightning_node_boot_counter.add(1, &boot_attrs);
		}
	}
}

pub fn add_lightning_payment(
	lightning_node_id: i64,
	amount_msat: u64,
	status: LightningPaymentStatus,
) {
	if let Some(m) = TELEMETRY.get() {
		let attrs = m.with_global_labels([
			KeyValue::new(ATTRIBUTE_LIGHTNING_NODE_ID, lightning_node_id.to_string()),
			KeyValue::new(ATTRIBUTE_STATUS, status.to_string()),
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

pub fn set_open_invoices(lightning_node_id: i64, count: usize) {
	if let Some(m) = TELEMETRY.get() {
		let attrs = m.with_global_labels([
			KeyValue::new(ATTRIBUTE_LIGHTNING_NODE_ID, lightning_node_id.to_string()),
		]);
		m.lightning_open_invoices_gauge.record(count as u64, &attrs)
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

pub fn set_vtxo_pool_metrics(pool: &BTreeMap<BlockHeight, BTreeMap<Amount, Vec<VtxoId>>>) {
	if TELEMETRY.get().is_none() { return; }

	#[derive(Copy, Clone)]
	struct Bucket {
		total: u64,
		max: u64,
		count: u32,
	}

	let block_height_tip = BLOCK_HEIGHT_TIP.load(Ordering::Relaxed) as u32;

	const LIFETIME_BUCKETS: &[(u32, &'static str)] = &[
		(6,        "0-5"),     // < 1 hour  (~10min blocks)
		(72,       "6-71"),    // < 12 hours
		(144,      "72-143"),  // < 24 hours
		(288,      "144-287"), // < 48 hours
		(u32::MAX, "288-*"),   // ≥ 48 hours
	];

	let mut lifetime_buckets = [Bucket { total: 0, max: 0, count: 0 }; 5];

	for (&expiry_height, vtxo_map) in pool {
		let expiry_height_delta = expiry_height.saturating_sub(block_height_tip);

		let bucket_ix = LIFETIME_BUCKETS.iter()
			.position(|(upper, _)| expiry_height_delta < *upper)
			.expect("Last bucket is u32::MAX, so this should never fail");

		let bucket_entry = &mut lifetime_buckets[bucket_ix];
		for (&amount, ids) in vtxo_map {
			let sats = amount.to_sat();
			let n = ids.len() as u32;

			bucket_entry.total += sats.saturating_mul(n as u64);
			bucket_entry.count += n;
			bucket_entry.max = cmp::max(bucket_entry.max, sats);
		}
	}
	for (i, &(_, label)) in LIFETIME_BUCKETS.iter().enumerate() {
		let bucket_entry = lifetime_buckets[i];
		set_vtxo_pool_metric(label, bucket_entry.total, bucket_entry.max, bucket_entry.count);
	}
}


fn set_vtxo_pool_metric(block_delta_label: &'static str, amount_total: u64, amount_max: u64, count: u32) {
	let Some(m) = TELEMETRY.get() else { return };

	let attrs = m.with_global_labels([
		KeyValue::new("blocks_until_expiry", block_delta_label),
	]);

	m.vtxo_pool_amount_gauge.record(amount_total, &attrs);
	m.vtxo_pool_amount_max_gauge.record(amount_max, &attrs);
	m.vtxo_pool_count_gauge.record(count as u64, &attrs);
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