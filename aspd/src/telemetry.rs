use std::time::Duration;

use bitcoin::secp256k1::PublicKey;
use bitcoin::Amount;
use bitcoin_ext::BlockHeight;
use opentelemetry::metrics::{Counter, Gauge};
use opentelemetry::{Key, Value};
use opentelemetry::{global, propagation::Extractor, KeyValue};
use opentelemetry::trace::{TracerProvider, Span};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::trace::{RandomIdGenerator, Sampler};
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::Registry;

use crate::cln::ClnNodeStateKind;
use crate::Config;
use crate::database::model::LightningPaymentStatus;

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

pub const METER_COUNTER_VERSION: &str = "version_counter";
pub const METER_COUNTER_MAIN_SPAWN: &str = "main_spawn_counter";
pub const METER_COUNTER_GRPC_REQUEST: &str = "grpc_requests_total";
pub const METER_COUNTER_GRPC_ERROR: &str = "grpc_errors_total";
pub const METER_COUNTER_UD_GRPC_IN_PROCESS: &str = "grpc_requests_in_progress";
pub const METER_HISTOGRAM_GRPC_LATENCY: &str = "grpc_request_duration_ms";
pub const METER_COUNTER_HANDSHAKE_VERSION: &str = "handshake_version_counter";
pub const METER_GAUGE_WALLET_BALANCE: &str = "wallet_balance_gauge";
pub const METER_GAUGE_BLOCK_HEIGHT: &str = "block_gauge";
pub const METER_GAUGE_LIGHTNING_NODE: &str = "lightning_node_gauge";
pub const METER_COUNTER_LIGHTNING_NODE_BOOT: &str = "lightning_node_boot_counter";
pub const METER_COUNTER_LIGHTNING_PAYMENT: &str = "lightning_payment_counter";
pub const METER_COUNTER_LIGHTNING_PAYMENT_VOLUME: &str = "lightning_payment_volume";
pub const METER_COUNTER_LIGHTNING_INVOICE_VERIFICATION: &str = "lightning_invoice_verification_counter";
pub const METER_GAUGE_LIGHTNING_INVOICE_VERIFICATION_QUEUE: &str = "lightning_invoice_verification_queue_gauge";

pub const ATTRIBUTE_ROUND_ID: &str = "round_id";
pub const ATTRIBUTE_BLOCKHEIGHT: &str = "blockheight";
pub const ATTRIBUTE_SYSTEM: &str = "system";
pub const ATTRIBUTE_SERVICE: &str = "service";
pub const ATTRIBUTE_METHOD: &str = "method";
pub const ATTRIBUTE_STATUS_CODE: &str = "status_code";

/// The [numeric status code](https://github.com/grpc/grpc/blob/v1.33.2/doc/statuscodes.md)
/// of the gRPC request.
pub const RPC_GRPC_STATUS_CODE: &str = "rpc.grpc.status_code";

#[derive(Debug, Clone)]
struct InnerMetrics {
	handshake_version_counter: Counter<u64>,
	wallet_balance_gauge: Gauge<u64>,
	block_height_gauge: Gauge<u64>,
	lightning_node_gauge: Gauge<u64>,
	lightning_node_boot_counter: Counter<u64>,
	lightning_payment_counter: Counter<u64>,
	lightning_payment_volume: Counter<u64>,
	lightning_invoice_verification_counter: Counter<u64>,
	lightning_invoice_verification_queue_gauge: Gauge<u64>,
}


#[derive(Debug, Clone)]
pub struct TelemetryMetrics {
	inner: Option<InnerMetrics>,
}

impl TelemetryMetrics {
	pub const fn disabled() -> Self {
		Self { inner: None }
	}

	pub fn init(config: &Config, public_key: PublicKey) -> TelemetryMetrics {
		let endpoint = match config.otel_collector_endpoint {
			Some(ref e) => e,
			None => return TelemetryMetrics::disabled(),
		};

		global::set_text_map_propagator(TraceContextPropagator::new());

		let trace_exporter = opentelemetry_otlp::SpanExporter::builder()
			.with_tonic()
			.with_endpoint(endpoint)
			.with_timeout(Duration::from_secs(3))
			.build().unwrap();

		let resource = Resource::builder()
			.with_attribute(KeyValue::new("service.name", "aspd"))
			.with_attribute(KeyValue::new("service.version", env!("CARGO_PKG_VERSION")))
			.with_attribute(KeyValue::new("aspd.public_key", public_key.to_string()))
			.with_attribute(KeyValue::new("aspd.network", config.network.to_string()))
			.with_attribute(KeyValue::new("aspd.round_interval", config.round_interval.as_secs().to_string()))
			.with_attribute(KeyValue::new("aspd.maximum_vtxo_amount",
				config.max_vtxo_amount.unwrap_or_else(|| Amount::ZERO).to_string()
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
		let aspd_telemetry = OpenTelemetryLayer::new(aspd_tracer);
		let subscriber = Registry::default().with(aspd_telemetry);
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
		let version_counter = meter.u64_counter(METER_COUNTER_VERSION).build();
		let handshake_version_counter = meter.u64_counter(METER_COUNTER_HANDSHAKE_VERSION).build();
		let wallet_balance_gauge = meter.u64_gauge(METER_GAUGE_WALLET_BALANCE).build();
		let block_height_gauge = meter.u64_gauge(METER_GAUGE_BLOCK_HEIGHT).build();
		let lightning_node_gauge = meter.u64_gauge(METER_GAUGE_LIGHTNING_NODE).build();
		let lightning_node_boot_counter = meter.u64_counter(METER_COUNTER_LIGHTNING_NODE_BOOT).build();
		let lightning_payment_counter = meter.u64_counter(METER_COUNTER_LIGHTNING_PAYMENT).build();
		let lightning_payment_volume = meter.u64_counter(METER_COUNTER_LIGHTNING_PAYMENT_VOLUME).build();
		let lightning_invoice_verification_counter = meter.u64_counter(METER_COUNTER_LIGHTNING_INVOICE_VERIFICATION).build();
		let lightning_invoice_verification_queue_gauge = meter.u64_gauge(METER_GAUGE_LIGHTNING_INVOICE_VERIFICATION_QUEUE).build();
		
		version_counter.add(1u64, &[KeyValue::new("version", env!("CARGO_PKG_VERSION"))]);

		TelemetryMetrics {
			inner: Some(InnerMetrics {
				handshake_version_counter,
				wallet_balance_gauge,
				block_height_gauge,
				lightning_node_gauge,
				lightning_node_boot_counter,
				lightning_payment_counter,
				lightning_payment_volume,
				lightning_invoice_verification_counter,
				lightning_invoice_verification_queue_gauge,
			})
		}
	}

	pub fn count_version(&self, version: &str) {
		if let Some(ref m) = self.inner {
			m.handshake_version_counter.add(1, &[KeyValue::new("version", version.to_owned())]);
		}
	}

	pub fn set_wallet_balance(&self, wallet_balance: Amount) {
		if let Some(ref m) = self.inner {
			m.wallet_balance_gauge.record(wallet_balance.to_sat(), &[]);
		}
	}

	pub fn set_block_height(&self, block_height: BlockHeight) {
		if let Some(ref m) = self.inner {
			m.block_height_gauge.record(block_height as u64, &[]);
		}
	}

	pub fn set_lightning_node_state(
		&self,
		lightning_node_uri: tonic::transport::Uri,
		lightning_node_id: Option<i64>,
		public_key: Option<PublicKey>,
		state: ClnNodeStateKind,
	) {
		let public_key_string = match public_key {
			Some(public_key) => public_key.to_string(),
			None => "".to_string(),
		};

		if let Some(ref m) = self.inner {
			for s in ClnNodeStateKind::get_all() {
				let value = if s == state {
					1
				} else {
					0
				};

				m.lightning_node_gauge.record(value, &[
					KeyValue::new("uri", lightning_node_uri.to_string()),
					KeyValue::new("lightning_node_id", lightning_node_id.unwrap_or(0).to_string()),
					KeyValue::new("public_key", public_key_string.clone()),
					KeyValue::new("state", s.as_str()),
				]);
			}

			if state == ClnNodeStateKind::Online {
				m.lightning_node_boot_counter.add(1, &[
					KeyValue::new("uri", lightning_node_uri.to_string()),
					KeyValue::new("lightning_node_id", lightning_node_id.unwrap_or(0).to_string()),
					KeyValue::new("public_key", public_key_string),
				]);
			}
		}
	}

	pub fn add_lightning_payment(
		&self,
		lightning_node_id: i64,
		amount_msat: u64,
		status: LightningPaymentStatus,
	) {
		if let Some(ref m) = self.inner {
			m.lightning_payment_counter.add(1, &[
				KeyValue::new("lightning_node_id", lightning_node_id.to_string()),
				KeyValue::new("status", status.to_string()),
			]);

			m.lightning_payment_volume.add(amount_msat/1000, &[
				KeyValue::new("lightning_node_id", lightning_node_id.to_string()),
				KeyValue::new("status", status.to_string()),
			]);
		}
	}

	pub fn add_invoice_verification(
		&self,
		lightning_node_id: i64,
		status: LightningPaymentStatus,
	) {
		if let Some(ref m) = self.inner {
			m.lightning_invoice_verification_counter.add(1, &[
				KeyValue::new("lightning_node_id", lightning_node_id.to_string()),
				KeyValue::new("status", status.to_string()),
			]);
		}
	}

	pub fn set_pending_invoice_verifications(
		&self,
		lightning_node_id: i64,
		count: usize,
	) {
		if let Some(ref m) = self.inner {
			m.lightning_invoice_verification_queue_gauge.record(count as u64, &[
				KeyValue::new("lightning_node_id", lightning_node_id.to_string()),
			])
		}
	}

	pub fn spawn_gauge(&self) -> Gauge<u64> {
		// nb this is only a function here to enforce that the telemetry was initialized
		let meter = global::meter_provider().meter(METER_ASPD);
		meter.u64_gauge(METER_COUNTER_MAIN_SPAWN).build()
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
