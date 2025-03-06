use std::time::Duration;
use anyhow::Error;
use bitcoin::Amount;
use opentelemetry::{global, propagation::Extractor, KeyValue};
use opentelemetry::metrics::Counter;
use opentelemetry::trace::TracerProvider;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::trace::{RandomIdGenerator, Sampler};
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::Registry;
use crate::App;

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

pub const METER_COUNTER_MAIN_SPAWN: &str = "main_spawn_counter";
pub const METER_COUNTER_GRPC_REQUEST: &str = "grpc_requests_total";
pub const METER_COUNTER_GRPC_ERROR: &str = "grpc_errors_total";
pub const METER_COUNTER_UD_GRPC_IN_PROCESS: &str = "grpc_requests_in_progress";
pub const METER_HISTOGRAM_GRPC_LATENCY: &str = "grpc_request_duration_ms";

pub const ATTRIBUTE_ROUND_ID: &str = "round_id";
pub const ATTRIBUTE_BLOCKHEIGHT: &str = "blockheight";
pub const ATTRIBUTE_SYSTEM: &str = "system";
pub const ATTRIBUTE_SERVICE: &str = "service";
pub const ATTRIBUTE_METHOD: &str = "method";
pub const ATTRIBUTE_STATUS_CODE: &str = "status_code";


pub fn init_telemetry(app: &App) -> Result<Option<Counter<u64>>, Error> {
	let resource = Resource::new(
		vec![
			KeyValue::new("service.name", "aspd"),
			KeyValue::new("aspd.pubic_key", app.asp_key.public_key().to_string()),
			KeyValue::new("aspd.network", app.config.network.to_string()),
			KeyValue::new("aspd.round_interval", app.config.round_interval.as_secs().to_string()),
			KeyValue::new("aspd.maximum_vtxo_amount",
				app.config.max_vtxo_amount.unwrap_or_else(|| Amount::ZERO).to_string(),
			)
		]);

	let otel_collector_endpoint = app.config.otel_collector_endpoint.clone();
	if otel_collector_endpoint.is_none() {
		return Ok(None);
	}

	global::set_text_map_propagator(TraceContextPropagator::new());

	let trace_exporter = opentelemetry_otlp::SpanExporter::builder()
		.with_tonic()
		.with_endpoint(otel_collector_endpoint.clone().unwrap())
		.with_timeout(Duration::from_secs(3))
		.build()?;

	let tracer_provider = opentelemetry_sdk::trace::TracerProvider::builder()
		.with_batch_exporter(trace_exporter, opentelemetry_sdk::runtime::Tokio)
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
		.map_err(|err| anyhow::anyhow!("Failed to set tracing subscriber: {:?}", err))?;

	let metrics_exporter = opentelemetry_otlp::MetricExporter::builder()
		// Build exporter using Delta Temporality (Defaults to Temporality::Cumulative)
		// .with_temporality(opentelemetry_sdk::metrics::Temporality::Delta)
		.with_tonic()
		.with_endpoint(otel_collector_endpoint.clone().unwrap())
		.with_timeout(Duration::from_secs(3))
		.build()?;

	let metrics_reader = PeriodicReader::builder(metrics_exporter, opentelemetry_sdk::runtime::Tokio).build();
	let provider = SdkMeterProvider::builder()
		.with_reader(metrics_reader)
		.with_resource(resource)
		.build();
	global::set_meter_provider(provider);

	let meter = global::meter_provider().meter(METER_ASPD);
	let spawn_counter = meter.u64_counter(METER_COUNTER_MAIN_SPAWN).build();

	Ok(Some(spawn_counter))
}

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
