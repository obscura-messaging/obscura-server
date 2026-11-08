use crate::config::{LogFormat, TelemetryConfig};
use opentelemetry::logs::{AnyValue, LogRecord, Logger, LoggerProvider, Severity};
use opentelemetry::{KeyValue, global};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{
    Resource,
    logs::BatchLogProcessor,
    logs::SdkLoggerProvider,
    metrics::PeriodicReader,
    metrics::SdkMeterProvider,
    propagation::TraceContextPropagator,
    trace::{BatchSpanProcessor, Sampler, SdkTracerProvider},
};
use opentelemetry_semantic_conventions::resource::{SERVICE_NAME, SERVICE_VERSION};
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::{EnvFilter, Registry, layer::SubscriberExt, util::SubscriberInitExt};

/// A guard that ensures OpenTelemetry providers are properly shut down and flushed when dropped.
// ... (TelemetryGuard implementation remains the same)
#[derive(Debug)]
pub struct TelemetryGuard {
    tracer: Option<SdkTracerProvider>,
    meter: Option<SdkMeterProvider>,
    logger: Option<SdkLoggerProvider>,
}

impl TelemetryGuard {
    #[allow(clippy::print_stderr)]
    pub fn shutdown(self) {
        if let Some(provider) = self.tracer
            && let Err(err) = provider.shutdown()
        {
            eprintln!("Error shutting down tracer provider: {err:?}");
        }
        if let Some(provider) = self.meter
            && let Err(err) = provider.shutdown()
        {
            eprintln!("Error shutting down meter provider: {err:?}");
        }
        if let Some(provider) = self.logger {
            // SdkLoggerProvider::shutdown returns a CompletableResultCode in some versions,
            // or a Result in others. We just call it to trigger the flush.
            let _ = provider.shutdown();
        }
    }
}

/// Initializes the OpenTelemetry tracing, metrics, and logging providers and hooks them into the tracing subscriber.
///
/// # Errors
/// Returns an error if any of the OTLP exporters fail to initialize.
///
/// # Panics
/// Panics if the default `EnvFilter` or tracing subscriber cannot be initialized.
pub fn init_telemetry(config: &TelemetryConfig) -> anyhow::Result<TelemetryGuard> {
    // 1. Build the Registry with EnvFilter
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "info".into())
        .add_directive("sqlx=warn".parse().expect("Invalid directive for sqlx"))
        .add_directive("tower_http=warn".parse().expect("Invalid directive for tower_http"))
        .add_directive("hyper=warn".parse().expect("Invalid directive for hyper"))
        .add_directive("opentelemetry=warn".parse().expect("Invalid directive for opentelemetry"))
        .add_directive("opentelemetry_sdk=warn".parse().expect("Invalid directive for opentelemetry_sdk"));

    let registry = Registry::default().with(filter);

    // 2. Initialize OTLP Layers (Optional)
    let (otel_layer, logger_layer, guard) = if let Some(endpoint) = &config.otlp_endpoint
        && !endpoint.is_empty()
    {
        let service_name = "obscura-server";
        let service_version = env!("CARGO_PKG_VERSION");

        // Configure Resource
        let resource = Resource::builder()
            .with_attributes(vec![
                KeyValue::new(SERVICE_NAME, service_name),
                KeyValue::new(SERVICE_VERSION, service_version),
            ])
            .build();

        // Setup Propagation
        global::set_text_map_propagator(TraceContextPropagator::new());

        // Setup Tracing
        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_tonic()
            .with_endpoint(endpoint.clone())
            .with_timeout(std::time::Duration::from_secs(config.export_timeout_secs.get()))
            .build()?;

        let tracer_provider = SdkTracerProvider::builder()
            .with_resource(resource.clone())
            .with_sampler(Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(config.trace_sampling_ratio))))
            .with_span_processor(BatchSpanProcessor::builder(exporter).build())
            .build();

        let tracer = opentelemetry::trace::TracerProvider::tracer(&tracer_provider, service_name);
        global::set_tracer_provider(tracer_provider.clone());

        // Setup Metrics
        let exporter = opentelemetry_otlp::MetricExporter::builder()
            .with_tonic()
            .with_endpoint(endpoint.clone())
            .with_timeout(std::time::Duration::from_secs(config.export_timeout_secs.get()))
            .build()?;

        let reader = PeriodicReader::builder(exporter)
            .with_interval(std::time::Duration::from_secs(config.metrics_export_interval_secs.get()))
            .build();
        let meter_provider = SdkMeterProvider::builder().with_resource(resource.clone()).with_reader(reader).build();
        global::set_meter_provider(meter_provider.clone());

        // Setup Logging
        let exporter = opentelemetry_otlp::LogExporter::builder()
            .with_tonic()
            .with_endpoint(endpoint.clone())
            .with_timeout(std::time::Duration::from_secs(config.export_timeout_secs.get()))
            .build()?;

        let logger_provider = SdkLoggerProvider::builder()
            .with_resource(resource)
            .with_log_processor(BatchLogProcessor::builder(exporter).build())
            .build();

        let logger = logger_provider.logger("obscura-server");
        let layer = OtelLogLayer::new(logger);

        let guard = TelemetryGuard {
            tracer: Some(tracer_provider),
            meter: Some(meter_provider),
            logger: Some(logger_provider),
        };

        (Some(OpenTelemetryLayer::new(tracer)), Some(layer), guard)
    } else {
        let guard = TelemetryGuard { tracer: None, meter: None, logger: None };
        (None, None, guard)
    };

    // 3. Compose Layers
    let registry = registry.with(otel_layer).with(logger_layer);

    match config.log_format {
        LogFormat::Text => {
            registry.with(tracing_subscriber::fmt::layer()).init();
        }
        LogFormat::Json => {
            registry.with(tracing_subscriber::fmt::layer().json()).init();
        }
    }

    Ok(guard)
}

/// Initializes a no-op telemetry provider for tests to silence warnings.
pub fn init_test_telemetry() {
    let provider = SdkMeterProvider::builder().build();
    global::set_meter_provider(provider);
}

/// A custom tracing layer that bridges tracing events to OpenTelemetry logs.
/// It specifically handles the "empty message" issue by promoting the 'error' field
/// to the log body if the message is empty (common when using #[instrument(err)]).
struct OtelLogLayer<L: Logger> {
    logger: L,
}

impl<L: Logger> OtelLogLayer<L> {
    const fn new(logger: L) -> Self {
        Self { logger }
    }
}

impl<L, S> tracing_subscriber::Layer<S> for OtelLogLayer<L>
where
    L: Logger + 'static,
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: tracing_subscriber::layer::Context<'_, S>) {
        let mut visitor = OtelLogVisitor::default();
        event.record(&mut visitor);

        let mut record = self.logger.create_log_record();

        let meta = event.metadata();

        // Map Severity
        let severity = match *meta.level() {
            tracing::Level::ERROR => Severity::Error,
            tracing::Level::WARN => Severity::Warn,
            tracing::Level::INFO => Severity::Info,
            tracing::Level::DEBUG => Severity::Debug,
            tracing::Level::TRACE => Severity::Trace,
        };
        record.set_severity_number(severity);
        record.set_severity_text(meta.level().as_str());
        record.set_target(meta.target().to_string());

        // Correlation: OTel global state handles trace/span IDs if the context is active
        let context = opentelemetry::Context::current();
        let span = opentelemetry::trace::TraceContextExt::span(&context);
        let span_context = span.span_context();
        if span_context.is_valid() {
            record.add_attributes(vec![
                ("trace_id", AnyValue::from(span_context.trace_id().to_string())),
                ("span_id", AnyValue::from(span_context.span_id().to_string())),
            ]);
        }

        // The Fix: Promote 'error' to Body if 'message' is empty
        let body = if visitor.message.is_empty() && !visitor.error.is_empty() {
            visitor.error.clone()
        } else {
            visitor.message
        };
        record.set_body(AnyValue::from(body));

        // Add other fields as attributes
        record.add_attributes(visitor.attributes.into_iter().map(|(k, v)| (k, AnyValue::from(v))));

        if !visitor.error.is_empty() {
            record.add_attributes(vec![("error", AnyValue::from(visitor.error))]);
        }

        self.logger.emit(record);
    }
}

#[derive(Default)]
struct OtelLogVisitor {
    message: String,
    error: String,
    attributes: Vec<(String, String)>,
}

impl tracing::field::Visit for OtelLogVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        let name = field.name();
        let val = format!("{value:?}");
        if name == "message" {
            self.message = val;
        } else if name == "error" {
            self.error = val;
        } else {
            self.attributes.push((name.to_string(), val));
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        let name = field.name();
        if name == "message" {
            self.message = value.to_string();
        } else if name == "error" {
            self.error = value.to_string();
        } else {
            self.attributes.push((name.to_string(), value.to_string()));
        }
    }
}
