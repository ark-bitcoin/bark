
use std::fmt;
use std::time::Duration;

use ark::rounds::RoundSeq;
use bdk_wallet::Balance;
use bitcoin::secp256k1::PublicKey;
use bitcoin::Amount;
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

use crate::Config;
use crate::ln::cln::ClnNodeStateKind;
use crate::database::ln::LightningPaymentStatus;
use crate::round::RoundStateKind;
use crate::wallet::WalletKind;

pub const TRACER_CAPTAIND: &str = "captaind";

pub const TRACE_RUN_ROUND: &str = "round";
pub const TRACE_RUN_ROUND_EMPTY: &str = "round_empty";
pub const TRACE_RUN_ROUND_POPULATED: &str = "round_populated";

pub const METER_CAPTAIND: &str = "captaind";

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

pub enum RoundStep {
	Attempt(Instant),
	ReceivePayments(Instant),
	SendVtxoProposal(Instant),
	ReceiveVtxoSignatures(Instant),
	CombineVtxoSignatures(Instant),
	ConstructVtxoTree(Instant),
	SendRoundProposal(Instant),
	ReceiveForfeitSignatures(Instant),
	SignOnChainTransaction(Instant),
	FinalStage(Instant),
	Persist(Instant),
}

impl RoundStep {

	// When changing this also change `get_all`
	pub fn as_str(&self) -> &'static str {
		match self {
			RoundStep::Attempt(_) => "round_attempt",
			RoundStep::ReceivePayments(_) => "round_receive_payments",
			RoundStep::SendVtxoProposal(_) => "round_send_vtxo_proposal",
			RoundStep::ReceiveVtxoSignatures(_) => "round_receive_vtxo_signatures",
			RoundStep::CombineVtxoSignatures(_) => "round_combine_vtxo_signatures",
			RoundStep::ConstructVtxoTree(_) => "round_construct_vtxo_tree",
			RoundStep::SendRoundProposal(_) => "round_send_round_proposal",
			RoundStep::ReceiveForfeitSignatures(_) => "round_receive_forfeit_signatures",
			RoundStep::SignOnChainTransaction(_) => "round_sign_on_chain_transaction",
			RoundStep::FinalStage(_) => "round_finalize_stage",
			RoundStep::Persist(_) => "round_persist",
		}
	}

	pub fn duration(&self) -> Duration {
		match self {
			RoundStep::Attempt(t) => Instant::now().duration_since(*t),
			RoundStep::ReceivePayments(t) => Instant::now().duration_since(*t),
			RoundStep::SendVtxoProposal(t) => Instant::now().duration_since(*t),
			RoundStep::ReceiveVtxoSignatures(t) => Instant::now().duration_since(*t),
			RoundStep::CombineVtxoSignatures(t) => Instant::now().duration_since(*t),
			RoundStep::ConstructVtxoTree(t) => Instant::now().duration_since(*t),
			RoundStep::SendRoundProposal(t) => Instant::now().duration_since(*t),
			RoundStep::ReceiveForfeitSignatures(t) => Instant::now().duration_since(*t),
			RoundStep::SignOnChainTransaction(t) => Instant::now().duration_since(*t),
			RoundStep::FinalStage(t) => Instant::now().duration_since(*t),
			RoundStep::Persist(t) => Instant::now().duration_since(*t),
		}
	}

	// When changing this also change `as_str`
	pub fn get_all() -> &'static [&'static str] {
		&[
			"round_attempt",
			"round_receive_payments",
			"round_send_vtxo_proposal",
			"round_receive_vtxo_signatures",
			"round_combine_vtxo_signatures",
			"round_construct_vtxo_tree",
			"round_send_round_proposal",
			"round_receive_forfeit_signatures",
			"round_sign_on_chain_transaction",
			"round_finalize_stage",
			"round_persist",
		]
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

/// Initialize open-telemetry.
///
/// MUST be called (only once) before registering or updating metrics.
pub fn init_telemetry(config: &Config, pubkey: PublicKey) {
	if config.otel_collector_endpoint.is_some() {
		TELEMETRY.set(Metrics::init(config, pubkey)).expect("Telemetry already initialized");
	}
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
	lightning_node_gauge: Gauge<u64>,
	lightning_node_boot_counter: Counter<u64>,
	lightning_payment_counter: Counter<u64>,
	lightning_payment_volume: Counter<u64>,
	lightning_invoice_verification_counter: Counter<u64>,
	lightning_invoice_verification_queue_gauge: Gauge<u64>,
	grpc_in_progress_counter: UpDownCounter<i64>,
	grpc_latency_histogram: Histogram<u64>,
	grpc_request_counter: Counter<u64>,
	grpc_error_counter: Counter<u64>,
}

impl Metrics {
	fn init(config: &Config, pubkey: PublicKey) -> Self {
		let endpoint = config.otel_collector_endpoint.as_ref().unwrap();

		global::set_text_map_propagator(TraceContextPropagator::new());

		let trace_exporter = opentelemetry_otlp::SpanExporter::builder()
			.with_tonic()
			.with_endpoint(endpoint.clone())
			.with_timeout(Duration::from_secs(10))
			.with_compression(Compression::Gzip)
			.build().unwrap();

		let resource = Resource::builder()
			.with_attribute(KeyValue::new(SERVICE_NAME, "captaind"))
			.with_attribute(KeyValue::new(SERVICE_VERSION, env!("CARGO_PKG_VERSION")))
			.with_attribute(KeyValue::new("captaind.pubkey", pubkey.to_string()))
			.with_attribute(KeyValue::new("captaind.network", config.network.to_string()))
			.with_attribute(KeyValue::new("captaind.round_interval", config.round_interval.as_secs().to_string()))
			.with_attribute(KeyValue::new("captaind.maximum_vtxo_amount",
				config.max_vtxo_amount.unwrap_or_else(|| Amount::ZERO).to_string(),
			))
			.build();

		let tracer_sampler = if let Some(sampler) = config.otel_tracing_sampler {
			Sampler::TraceIdRatioBased(sampler)
		} else {
			Sampler::AlwaysOff
		};

		let tracer_provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
			.with_batch_exporter(trace_exporter)
			.with_sampler(tracer_sampler)
			.with_id_generator(RandomIdGenerator::default())
			.with_max_events_per_span(64)
			.with_max_attributes_per_span(16)
			.with_resource(resource.clone())
			.build();

		let captaind_tracer = tracer_provider.tracer(TRACER_CAPTAIND);

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

		let meter = global::meter_provider().meter(METER_CAPTAIND);
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
		let pending_forfeit_gauge = meter.u64_gauge("pending_forfeit_gauge").build();
		let lightning_node_gauge = meter.u64_gauge("lightning_node_gauge").build();
		let lightning_node_boot_counter = meter.u64_counter("lightning_node_boot_counter").build();
		let lightning_payment_counter = meter.u64_counter("lightning_payment_counter").build();
		let lightning_payment_volume = meter.u64_counter("lightning_payment_volume").build();
		let lightning_invoice_verification_counter = meter.u64_counter("lightning_invoice_verification_counter").build();
		let lightning_invoice_verification_queue_gauge = meter.u64_gauge("lightning_invoice_verification_queue_gauge").build();
		// gRPC metrics
		let grpc_in_progress_counter = meter.i64_up_down_counter("grpc_requests_in_progress").build();
		let grpc_latency_histogram = meter.u64_histogram("grpc_request_duration_ms").build();
		let grpc_request_counter = meter.u64_counter("grpc_requests_total").build();
		let grpc_error_counter = meter.u64_counter("grpc_errors_total").build();

		// log the current server version
		meter.u64_counter("server_version_counter").build().add(
			1u64, &[KeyValue::new(ATTRIBUTE_SERVER_VERSION, env!("CARGO_PKG_VERSION"))],
		);

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
			lightning_node_gauge,
			lightning_node_boot_counter,
			lightning_payment_counter,
			lightning_payment_volume,
			lightning_invoice_verification_counter,
			lightning_invoice_verification_queue_gauge,
			grpc_in_progress_counter,
			grpc_latency_histogram,
			grpc_request_counter,
			grpc_error_counter,
		}
	}
}

pub fn worker_spawned(worker: &str) {
	if let Some(m) = TELEMETRY.get() {
		m.spawn_counter.add(1, &[KeyValue::new(ATTRIBUTE_WORKER, worker.to_owned())]);
	}
}

pub fn worker_dropped(worker: &str) {
	if let Some(m) = TELEMETRY.get() {
		m.spawn_counter.add(-1, &[KeyValue::new(ATTRIBUTE_WORKER, worker.to_owned())]);
	}
}

pub fn count_bark_version(client: Option<String>) {
	if let Some(m) = TELEMETRY.get() {
		let client = client.unwrap_or_else(|| format!("UNKNOWN"));
		m.bark_version_counter.add(1, &[KeyValue::new(ATTRIBUTE_BARK_VERSION, client)]);
	}
}

pub fn count_protocol_version(pver: u64) {
	if let Some(m) = TELEMETRY.get() {
		m.protocol_version_counter.add(1, &[KeyValue::new(ATTRIBUTE_PROTOCOL_VERSION, Value::I64(pver as i64))]);
	}
}

pub fn set_wallet_balance(wallet_kind: WalletKind, wallet_balance: Balance) {
	if let Some(m) = TELEMETRY.get() {
		m.wallet_balance_gauge.record(wallet_balance.confirmed.to_sat(), &[
			KeyValue::new(ATTRIBUTE_KIND, wallet_kind.to_string()),
			KeyValue::new(ATTRIBUTE_TYPE, "confirmed"),
		]);
		m.wallet_balance_gauge.record(wallet_balance.immature.to_sat(), &[
			KeyValue::new(ATTRIBUTE_KIND, wallet_kind.to_string()),
			KeyValue::new(ATTRIBUTE_TYPE, "immature"),
		]);
		m.wallet_balance_gauge.record(wallet_balance.trusted_pending.to_sat(), &[
			KeyValue::new(ATTRIBUTE_KIND, wallet_kind.to_string()),
			KeyValue::new(ATTRIBUTE_TYPE, "trusted_pending"),
		]);
		m.wallet_balance_gauge.record(wallet_balance.untrusted_pending.to_sat(), &[
			KeyValue::new(ATTRIBUTE_KIND, wallet_kind.to_string()),
			KeyValue::new(ATTRIBUTE_TYPE, "untrusted_pending"),
		]);
	}
}

pub fn set_block_height(block_height: BlockHeight) {
	if let Some(m) = TELEMETRY.get() {
		m.block_height_gauge.record(block_height as u64, &[]);
	}
}

// Initialize a new round and clear out the old data.
pub fn set_round_seq(round_seq: RoundSeq) {
	if let Some(m) = TELEMETRY.get() {
		m.round_seq_gauge.record(round_seq.inner(), &[]);
		m.round_attempt_gauge.record(0, &[]);
		m.round_input_volume_gauge.record(0, &[]);
		m.round_input_count_gauge.record(0, &[]);
		m.round_output_count_gauge.record(0, &[]);
		m.round_offboard_count_gauge.record(0, &[]);

		for s in RoundStep::get_all() {
			m.round_step_duration_gauge.record(0, &[
				KeyValue::new(ATTRIBUTE_ROUND_STEP, *s),
			]);
		}

		for s in RoundStateKind::get_all() {
			m.round_state_gauge.record(0, &[
				KeyValue::new(ATTRIBUTE_STATUS, s.as_str()),
			]);
		}
	}
}

pub fn set_round_attempt(attempt: usize) {
	if let Some(m) = TELEMETRY.get() {
		m.round_attempt_gauge.record(attempt as u64, &[]);
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

			m.round_state_gauge.record(value, &[
				KeyValue::new(ATTRIBUTE_STATUS, s.as_str()),
			]);
		}
	}
}

pub fn set_round_step_duration(round_step: RoundStep) {
	if let Some(m) = TELEMETRY.get() {
		m.round_step_duration_gauge.record(round_step.duration().as_millis() as u64, &[
			KeyValue::new(ATTRIBUTE_ROUND_STEP, round_step.as_str()),
		]);
	}
}

pub fn set_round_metrics(
	input_volume: Amount,
	input_count: usize,
	output_count: usize,
	offboard_count: usize,
) {
	if let Some(m) = TELEMETRY.get() {
		m.round_input_volume_gauge.record(input_volume.to_sat(), &[]);
		m.round_input_count_gauge.record(input_count as u64, &[]);
		m.round_output_count_gauge.record(output_count as u64, &[]);
		m.round_offboard_count_gauge.record(offboard_count as u64, &[]);
	}
}

pub fn set_pending_expired_rounds_count(pending_expired_rounds_count: usize) {
	if let Some(m) = TELEMETRY.get() {
		m.pending_expired_operation_gauge.record(pending_expired_rounds_count as u64, &[
			KeyValue::new(ATTRIBUTE_TYPE, "rounds"),
		]);
	}
}

pub fn set_pending_expired_boards_count(pending_expired_boards_count: usize) {
	if let Some(m) = TELEMETRY.get() {
		m.pending_expired_operation_gauge.record(pending_expired_boards_count as u64, &[
			KeyValue::new(ATTRIBUTE_TYPE, "boards"),
		]);
	}
}

pub fn set_pending_sweeper_stats(
	pending_tx_count: usize,
	pending_tx_volume: u64,
	pending_utxo_count: usize,
) {
	if let Some(m) = TELEMETRY.get() {
		m.pending_sweeper_gauge.record(pending_tx_count as u64, &[
			KeyValue::new(ATTRIBUTE_TYPE, "transaction_count"),
		]);
		m.pending_sweeper_gauge.record(pending_tx_volume, &[
			KeyValue::new(ATTRIBUTE_TYPE, "transaction_volume"),
		]);
		m.pending_sweeper_gauge.record(pending_utxo_count as u64, &[
			KeyValue::new(ATTRIBUTE_TYPE, "utxo_count"),
		]);
	}
}

pub fn set_forfeit_metrics(
	pending_exit_tx_count: usize,
	pending_exit_volume: u64,
	pending_claim_count: usize,
	pending_claim_volume: u64,
) {
	if let Some(ref m) = TELEMETRY.get() {
		m.pending_forfeit_gauge.record(pending_exit_tx_count as u64, &[
			KeyValue::new(ATTRIBUTE_TYPE, "pending_exit_transaction_count"),
		]);
		m.pending_forfeit_gauge.record(pending_exit_volume as u64, &[
			KeyValue::new(ATTRIBUTE_TYPE, "pending_exit_transaction_volume"),
		]);
		m.pending_forfeit_gauge.record(pending_claim_count as u64, &[
			KeyValue::new(ATTRIBUTE_TYPE, "pending_claim_count"),
		]);
		m.pending_forfeit_gauge.record(pending_claim_volume as u64, &[
			KeyValue::new(ATTRIBUTE_TYPE, "pending_claim_volume"),
		])
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

			m.lightning_node_gauge.record(value, &[
				KeyValue::new(ATTRIBUTE_URI, lightning_node_uri.to_string()),
				KeyValue::new(ATTRIBUTE_LIGHTNING_NODE_ID, lightning_node_id.unwrap_or(0).to_string()),
				KeyValue::new(ATTRIBUTE_PUBKEY, pubkey_string.clone()),
				KeyValue::new(ATTRIBUTE_STATUS, s.as_str()),
			]);
		}

		if state == ClnNodeStateKind::Online {
			m.lightning_node_boot_counter.add(1, &[
				KeyValue::new(ATTRIBUTE_URI, lightning_node_uri.to_string()),
				KeyValue::new(ATTRIBUTE_LIGHTNING_NODE_ID, lightning_node_id.unwrap_or(0).to_string()),
				KeyValue::new(ATTRIBUTE_PUBKEY, pubkey_string),
			]);
		}
	}
}

pub fn add_lightning_payment(lightning_node_id: i64, amount_msat: u64, status: LightningPaymentStatus) {
	if let Some(m) = TELEMETRY.get() {
		m.lightning_payment_counter.add(1, &[
			KeyValue::new(ATTRIBUTE_LIGHTNING_NODE_ID, lightning_node_id.to_string()),
			KeyValue::new(ATTRIBUTE_STATUS, status.to_string()),
		]);

		m.lightning_payment_volume.add(amount_msat / 1000, &[
			KeyValue::new(ATTRIBUTE_LIGHTNING_NODE_ID, lightning_node_id.to_string()),
			KeyValue::new(ATTRIBUTE_STATUS, status.to_string()),
		]);
	}
}

pub fn add_invoice_verification(lightning_node_id: i64, status: LightningPaymentStatus) {
	if let Some(m) = TELEMETRY.get() {
		m.lightning_invoice_verification_counter.add(1, &[
			KeyValue::new(ATTRIBUTE_LIGHTNING_NODE_ID, lightning_node_id.to_string()),
			KeyValue::new(ATTRIBUTE_STATUS, status.to_string()),
		]);
	}
}

pub fn set_pending_invoice_verifications(lightning_node_id: i64, count: usize) {
	if let Some(m) = TELEMETRY.get() {
		m.lightning_invoice_verification_queue_gauge.record(count as u64, &[
			KeyValue::new(ATTRIBUTE_LIGHTNING_NODE_ID, lightning_node_id.to_string()),
		])
	}
}

pub fn add_grpc_in_progress(attributes: &[KeyValue]) {
	if let Some(m) = TELEMETRY.get() {
		m.grpc_request_counter.add(1, attributes);
		m.grpc_in_progress_counter.add(1, attributes);
	}
}

pub fn record_grpc_latency(duration: Duration, attributes: &[KeyValue]) {
	if let Some(m) = TELEMETRY.get() {
		m.grpc_latency_histogram.record(duration.as_millis() as u64, attributes);
	}
}

pub fn add_grpc_error(attributes: &[KeyValue]) {
	if let Some(m) = TELEMETRY.get() {
		m.grpc_error_counter.add(1, attributes);
	}
}

pub fn drop_grpc_in_progress(attributes: &[KeyValue]) {
	if let Some(m) = TELEMETRY.get() {
		m.grpc_in_progress_counter.add(-1, attributes);
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
