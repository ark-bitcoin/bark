use std::time::Duration;
use bdk_wallet::Balance;
use bitcoin::secp256k1::PublicKey;
use bitcoin::Amount;
use bitcoin_ext::BlockHeight;
use opentelemetry::metrics::{Counter, Gauge, Histogram, UpDownCounter};
use opentelemetry::{Key, Value};
use opentelemetry::{global, propagation::Extractor, KeyValue};
use opentelemetry::trace::{TracerProvider, Span};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::trace::{RandomIdGenerator, Sampler};
use tokio::sync::OnceCell;
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{EnvFilter, Registry};
use crate::cln::ClnNodeStateKind;
use crate::Config;
use crate::database::model::LightningPaymentStatus;
use crate::round::RoundStateKind;
use crate::wallet::WalletKind;

pub const TRACER_ASPD: &str = "aspd";

pub const TRACE_RUN_ROUND: &str = "round";
pub const TRACE_RUN_ROUND_EMPTY: &str = "round_empty";
pub const TRACE_RUN_ROUND_POPULATED: &str = "round_populated";
pub const TRACE_RUN_ROUND_ATTEMPT: &str = "round_attempt";
pub const TRACE_RUN_ROUND_RECEIVE_PAYMENTS: &str = "round_receive_payments";
pub const TRACE_RUN_ROUND_SEND_VTXO_PROPOSAL: &str = "round_send_vtxo_proposal";
pub const TRACE_RUN_ROUND_RECEIVE_VTXO_SIGNATURES: &str = "round_receive_vtxo_signatures";
pub const TRACE_RUN_ROUND_COMBINE_VTXO_SIGNATURES: &str = "round_combine_vtxo_signatures";
pub const TRACE_RUN_ROUND_CONSTRUCT_VTXO_TREE: &str = "round_construct_vtxo_tree";
pub const TRACE_RUN_ROUND_SEND_ROUND_PROPOSAL: &str = "round_send_round_proposal";
pub const TRACE_RUN_ROUND_RECEIVING_FORFEIT_SIGNATURES: &str = "round_receiving_forfeit_signatures";
pub const TRACE_RUN_ROUND_FINALIZING: &str = "round_final_stage";
pub const TRACE_RUN_ROUND_PERSIST: &str = "round_persist";

pub const METER_ASPD: &str = "aspd";

pub const ATTRIBUTE_WORKER: &str = "worker";
pub const ATTRIBUTE_STATUS: &str = "status";
pub const ATTRIBUTE_ERROR: &str = "error";
pub const ATTRIBUTE_TYPE: &str = "type";
pub const ATTRIBUTE_KIND: &str = "kind";
pub const ATTRIBUTE_URI: &str = "uri";
pub const ATTRIBUTE_PUBLIC_KEY: &str = "public_key";
pub const ATTRIBUTE_VERSION: &str = "version";
pub const ATTRIBUTE_ROUND_ID: &str = "round_id";
pub const ATTRIBUTE_LIGHTNING_NODE_ID: &str = "lightning_node_id";

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
pub fn init_telemetry(config: &Config, public_key: PublicKey) {
	if config.otel_collector_endpoint.is_some() {
		TELEMETRY.set(Metrics::init(config, public_key)).expect("Telemetry already initialized");
	}
}

#[derive(Debug)]
struct Metrics {
	spawn_counter: UpDownCounter<i64>,
	handshake_version_counter: Counter<u64>,
	wallet_balance_gauge: Gauge<u64>,
	block_height_gauge: Gauge<u64>,
	round_gauge: Gauge<u64>,
	round_attempt_gauge: Gauge<u64>,
	round_volume_gauge: Gauge<u64>,
	round_vtxo_count_gauge: Gauge<u64>,
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
	fn init(config: &Config, public_key: PublicKey) -> Self {
		let endpoint = config.otel_collector_endpoint.as_ref().unwrap();

		global::set_text_map_propagator(TraceContextPropagator::new());

		let trace_exporter = opentelemetry_otlp::SpanExporter::builder()
			.with_tonic()
			.with_endpoint(endpoint.clone())
			.with_timeout(Duration::from_secs(3))
			.build().unwrap();

		let resource = Resource::builder()
			.with_attribute(KeyValue::new(SERVICE_NAME, "aspd"))
			.with_attribute(KeyValue::new(SERVICE_VERSION, env!("CARGO_PKG_VERSION")))
			.with_attribute(KeyValue::new("aspd.public_key", public_key.to_string()))
			.with_attribute(KeyValue::new("aspd.network", config.network.to_string()))
			.with_attribute(KeyValue::new("aspd.round_interval", config.round_interval.as_secs().to_string()))
			.with_attribute(KeyValue::new("aspd.maximum_vtxo_amount",
				config.max_vtxo_amount.unwrap_or_else(|| Amount::ZERO).to_string(),
			))
			.build();

		let tracer_provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
			.with_batch_exporter(trace_exporter)
			.with_sampler(Sampler::AlwaysOn)
			.with_id_generator(RandomIdGenerator::default())
			.with_max_events_per_span(64)
			.with_max_attributes_per_span(16)
			.with_resource(resource.clone())
			.build();

		let aspd_tracer = tracer_provider.tracer(TRACER_ASPD);

		global::set_tracer_provider(tracer_provider);

		// Set up the tracing subscriber
		let filter = EnvFilter::from_default_env()
			.add_directive("h2=off".parse().unwrap());
		let aspd_telemetry = OpenTelemetryLayer::new(aspd_tracer);
		let subscriber = Registry::default()
			.with(filter)
			.with(aspd_telemetry);
		tracing::subscriber::set_global_default(subscriber)
			.map_err(|err| anyhow::anyhow!("Failed to set tracing subscriber: {:?}", err)).unwrap();

		let metrics_exporter = opentelemetry_otlp::MetricExporter::builder()
			// Build exporter using Delta Temporality (Defaults to Temporality::Cumulative)
			// .with_temporality(opentelemetry_sdk::metrics::Temporality::Delta)
			.with_tonic()
			.with_endpoint(endpoint)
			.with_timeout(Duration::from_secs(3))
			.build().unwrap();

		let metrics_reader = PeriodicReader::builder(metrics_exporter).build();
		let provider = SdkMeterProvider::builder()
			.with_reader(metrics_reader)
			.with_resource(resource)
			.build();
		global::set_meter_provider(provider);

		let meter = global::meter_provider().meter(METER_ASPD);
		let spawn_counter = meter.i64_up_down_counter("spawn_counter").build();
		let version_counter = meter.u64_counter("version_counter").build();
		let handshake_version_counter = meter.u64_counter("handshake_version_counter").build();
		let wallet_balance_gauge = meter.u64_gauge("wallet_balance_gauge").build();
		let block_height_gauge = meter.u64_gauge("block_gauge").build();
		let round_gauge = meter.u64_gauge("round_gauge").build();
		let round_attempt_gauge = meter.u64_gauge("round_attempt_gauge").build();
		let round_volume_gauge = meter.u64_gauge("round_volume_gauge").build();
		let round_vtxo_count_gauge = meter.u64_gauge("round_vtxo_count_gauge").build();
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

		version_counter.add(1u64, &[KeyValue::new(ATTRIBUTE_VERSION, env!("CARGO_PKG_VERSION"))]);

		Metrics {
			spawn_counter,
			handshake_version_counter,
			wallet_balance_gauge,
			block_height_gauge,
			round_gauge,
			round_attempt_gauge,
			round_volume_gauge,
			round_vtxo_count_gauge,
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

pub fn count_version(version: &str) {
	if let Some(m) = TELEMETRY.get() {
		m.handshake_version_counter.add(1, &[KeyValue::new(ATTRIBUTE_VERSION, version.to_owned())]);
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

pub fn set_round_state(round_id: usize, state: RoundStateKind) {
	if let Some(m) = TELEMETRY.get() {
		for s in RoundStateKind::get_all() {
			let value = if *s == state {
				1
			} else {
				0
			};

			m.round_gauge.record(value, &[
				KeyValue::new(ATTRIBUTE_ROUND_ID, round_id.to_string()),
				KeyValue::new(ATTRIBUTE_STATUS, s.as_str()),
			]);
		}
	}
}

pub fn set_round_metrics(round_id: usize, attempt: usize, state: RoundStateKind) {
	if let Some(m) = TELEMETRY.get() {
		set_round_state(round_id, state.clone());

		m.round_attempt_gauge.record(attempt as u64, &[
			KeyValue::new(ATTRIBUTE_ROUND_ID, round_id.to_string()),
		]);
	}
}

pub fn set_full_round_metrics(
	round_id: usize,
	attempt: usize,
	state: RoundStateKind,
	volume: Amount,
	vtxo_count: usize,
) {
	if let Some(m) = TELEMETRY.get() {
		set_round_metrics(round_id, attempt, state.clone());

		m.round_volume_gauge.record(volume.to_sat(), &[
			KeyValue::new(ATTRIBUTE_ROUND_ID, round_id.to_string()),
		]);
		m.round_vtxo_count_gauge.record(vtxo_count as u64, &[
			KeyValue::new(ATTRIBUTE_ROUND_ID, round_id.to_string()),
		]);
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
	public_key: Option<PublicKey>,
	state: ClnNodeStateKind,
) {
	let public_key_string = match public_key {
		Some(public_key) => public_key.to_string(),
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
				KeyValue::new(ATTRIBUTE_PUBLIC_KEY, public_key_string.clone()),
				KeyValue::new(ATTRIBUTE_STATUS, s.as_str()),
			]);
		}

		if state == ClnNodeStateKind::Online {
			m.lightning_node_boot_counter.add(1, &[
				KeyValue::new(ATTRIBUTE_URI, lightning_node_uri.to_string()),
				KeyValue::new(ATTRIBUTE_LIGHTNING_NODE_ID, lightning_node_id.unwrap_or(0).to_string()),
				KeyValue::new(ATTRIBUTE_PUBLIC_KEY, public_key_string),
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
pub trait SpanExt: Span {
	fn set_int_attr(&mut self, key: impl Into<Key>, int: impl TryInto<i64>) {
		self.set_attribute(KeyValue::new(key, Value::I64(int.try_into().unwrap_or(-1))));
	}
}
impl<T: Span> SpanExt for T {}

pub struct MetadataMap<'a>(pub &'a tonic::metadata::MetadataMap);

impl<'a> Extractor for MetadataMap<'a> {
	/// Get a value for a key from the MetadataMap.  If the value can't be converted to &str, returns None
	fn get(&self, key: &str) -> Option<&str> {
		self.0.get(key).and_then(|metadata| metadata.to_str().ok())
	}

	/// Collect all the keys from the MetadataMap.
	fn keys(&self) -> Vec<&str> {
		self.0
			.keys()
			.map(|key| match key {
				tonic::metadata::KeyRef::Ascii(v) => v.as_str(),
				tonic::metadata::KeyRef::Binary(v) => v.as_str(),
			})
			.collect::<Vec<_>>()
	}
}