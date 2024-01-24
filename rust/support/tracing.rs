// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

use futures_util::future::BoxFuture;
use std::collections::HashMap;
use std::ffi::{c_char, c_int, c_void, CStr};
use std::fmt::Debug;
use std::hash::Hash;
use std::io::Write;
use std::ptr::NonNull;
use std::str::Bytes;
use std::{fs::File, os::fd::FromRawFd};

use async_trait::async_trait;
use opentelemetry::sdk::export::trace::{self, ExportResult, SpanExporter};
use opentelemetry::sdk::propagation::TraceContextPropagator;
use opentelemetry::KeyValue;
use opentelemetry_api::propagation::{Extractor, TextMapPropagator};
use opentelemetry_api::trace::{Span, Tracer, TracerProvider};

extern crate async_trait;
extern crate opentelemetry;
extern crate opentelemetry_api;

const HELLO_RANDOM_START_BYTE: usize = 6;
const HELLO_RANDOM_END_BYTE: usize = 38;

/// Converts a string object into an opentelemetry context by using a
/// Hashmap trace context propagator.
#[allow(dead_code)]
pub(crate) fn extract_context(context_str: &str) -> opentelemetry_api::Context {
    let trace_context_propagator = TraceContextPropagator::new();
    let mut extractor = PropagationContext(HashMap::new());
    extractor
        .0
        .insert("traceparent".to_string(), context_str.to_string());
    trace_context_propagator.extract(&extractor)
}

/// Converts a c_char to a str type.
#[allow(dead_code)]
pub(crate) fn convert_cstring<'a>(cstr: *const c_char) -> Option<&'a str> {
    NonNull::new(cstr.cast_mut())
        .map(|nptr| unsafe { CStr::from_ptr(nptr.as_ptr()) })
        .and_then(|cstr| cstr.to_str().ok())
        .filter(|str| !str.is_empty())
}

/// Hashmap that implements the Extractor trait so that Opentelemetry knows
/// how to get context information out of it.
#[derive(Debug, Clone)]
struct PropagationContext(HashMap<String, String>);

/// Implementing the extractor trait from OpenTelemetry propagation.
/// This tells OT how to get the context out of the hashmap.
impl Extractor for PropagationContext {
    fn get(&self, key: &str) -> Option<&str> {
        let key = key.to_string();
        self.0.get(&key).map(|v| v.as_str())
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(|k| k.as_str()).collect()
    }
}

/// Creating an object to hold information about the trace context,
/// And where to write the serialized data to.
#[derive(Debug)]
pub struct SandwichTracer {
    /// Opentelemetry tracer object, used to spawn spans
    tracer: opentelemetry::sdk::trace::Tracer,

    /// Keeping the tracer provider in scope keeps the buffer object open``
    _tracer_provider: opentelemetry::sdk::trace::TracerProvider,

    /// Opentelemetry Context, ensures context propogation
    ctx: opentelemetry_api::Context,

    /// Owning the current span for async lifecyle management of it
    pub current_span: Option<opentelemetry::sdk::trace::Span>,
}

impl SandwichTracer {
    /// Create a new SandwichTracer with a context and exporter.
    pub fn new<W: Write + Debug + Send + 'static>(
        ctx: opentelemetry_api::Context,
        exporter: SandwichSpanExporter<W>,
    ) -> Self {
        let tracer_provider = opentelemetry::sdk::trace::TracerProvider::builder()
            .with_simple_exporter(exporter)
            .build();
        let tracer = tracer_provider.versioned_tracer("sandwichTracer", None, None);

        SandwichTracer {
            ctx,
            _tracer_provider: tracer_provider,
            tracer,
            current_span: None,
        }
    }

    /// Creates a span to keep the context in the span data, and updates the current span reference.
    pub fn create_span(
        &mut self,
        span_name: &'static str,
    ) -> Option<&opentelemetry::sdk::trace::Span> {
        let span = self.tracer.start_with_context(span_name, &self.ctx.clone());
        self.current_span = Some(span);
        self.current_span.as_ref()
    }

    /// Ends the span and clears out the current span reference in addition to kicking off the exporting process for the span.
    pub fn end_current_span(&mut self) {
        if let Some(mut current_span) = self.current_span.take() {
            current_span.end();
        }
    }
}

/// Ends any currently running span in the tracer, in case it has been forgotten.
impl Drop for SandwichTracer {
    fn drop(&mut self) {
        self.end_current_span()
    }
}

/// An exporter that serializes spans with protobuf and writes bytes to a generic
/// object that implements the write trait.
#[derive(Debug)]
pub struct SandwichSpanExporter<W>(W)
where
    W: Write;

impl<W: Write> SandwichSpanExporter<W> {
    pub fn new(w: W) -> Self {
        Self(w)
    }
}

/// Implementing this trait lets us use this object as an OpenTelemetry exporter.
#[async_trait]
impl<W> SpanExporter for SandwichSpanExporter<W>
where
    W: Write + Debug + Send + 'static,
{
    fn export(&mut self, batch: Vec<trace::SpanData>) -> BoxFuture<'static, ExportResult> {
        use protobuf::Message;

        let mut encoded_spans = Vec::new();

        for span_data in batch {
            let proto_span: pb::Span = SpanData(span_data).into();

            match proto_span.write_to_bytes() {
                Ok(encoded_span_data) => {
                    encoded_spans
                        .extend_from_slice(&(encoded_span_data.len() as u32).to_le_bytes());
                    encoded_spans.extend_from_slice(&encoded_span_data);
                }
                Err(_) => continue,
            }
        }
        if !encoded_spans.is_empty() {
            let _ = self.0.write_all(encoded_spans.as_slice());
        }

        Box::pin(std::future::ready(Ok(())))
    }
}

/// Wrapping SpanData so we can write an implementation on the type.
struct SpanData(trace::SpanData);

/// Converts SpanData into the protobuf version of the same information.
impl From<SpanData> for pb::Span {
    fn from(source_span: SpanData) -> Self {
        let source_span = source_span.0;

        pb::Span {
            trace_id: source_span.span_context.trace_id().to_bytes().to_vec(),
            span_id: source_span.span_context.span_id().to_bytes().to_vec(),
            trace_state: source_span.span_context.trace_state().header(),
            parent_span_id: Vec::new(),
            name: source_span.name.into_owned(),
            kind: pb::span::SpanKind::SPAN_KIND_UNSPECIFIED.into(),
            start_time_unix_nano: to_nanos(source_span.start_time),
            end_time_unix_nano: to_nanos(source_span.end_time),
            dropped_attributes_count: source_span.attributes.dropped_count(),
            attributes: Vec::new(),
            dropped_events_count: source_span.events.dropped_count(),
            events: source_span
                .events
                .into_iter()
                .map(|event| pb::span::Event {
                    time_unix_nano: to_nanos(event.timestamp),
                    name: event.name.into(),
                    attributes: event
                        .attributes
                        .into_iter()
                        .map(|attribute| pb::KeyValue {
                            key: attribute.key.to_string(),
                            value: protobuf::MessageField::some(pb::AnyValue {
                                value: Some(pb::any_value::Value::StringValue(
                                    attribute.value.to_string(),
                                )),
                                special_fields: protobuf::SpecialFields::new(),
                            }),
                            special_fields: protobuf::SpecialFields::new(),
                        })
                        .collect(),
                    dropped_attributes_count: event.dropped_attributes_count,
                    special_fields: protobuf::SpecialFields::new(),
                })
                .collect(),
            dropped_links_count: source_span.links.dropped_count(),
            links: Vec::new(),
            status: None.into(),
            special_fields: protobuf::SpecialFields::new(),
        }
    }
}

/// Converts SystemTime to a u64 representing the time with nanosecond accuracy.
fn to_nanos(time: std::time::SystemTime) -> u64 {
    time.duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_else(|_| std::time::Duration::from_secs(0))
        .as_nanos() as u64
}

/// Extracts the random from the client and server hello message buffer.
pub fn extract_hello_random_str(hello_buf: &[u8]) -> String {
    if hello_buf.len() < 38 || hello_buf.len() < 2 {
        return "Random was formatted incorrectly.".to_string();
    }

    let random_bytes = &hello_buf[HELLO_RANDOM_START_BYTE..HELLO_RANDOM_END_BYTE];
    format!("{:x?}", random_bytes)
}

/// Converts the alert integer type to a more human readable version for events.
pub(crate) fn ssl_alert_desc(k: i32) -> Option<&'static str> {
    match k {
        0 => Some("Close Notify"),
        10 => Some("Unexpected Message"),
        20 => Some("Bad Record MAC"),
        21 => Some("Decryption Failed"),
        22 => Some("Record Overflow"),
        30 => Some("Decompression Failure"),
        40 => Some("Handshake Failure"),
        41 => Some("No Certificate"),
        42 => Some("Bad Certificate"),
        43 => Some("Unsupported Certificate"),
        44 => Some("Certificate Revoked"),
        45 => Some("Certificate Expired"),
        46 => Some("Certificate Unknown"),
        47 => Some("Illegal Parameter"),
        48 => Some("Unkown CA"),
        49 => Some("Access Denied"),
        50 => Some("Decode Error"),
        51 => Some("Decrypt Error"),
        60 => Some("Export Restriction"),
        70 => Some("Protocol Version"),
        71 => Some("Insufficient Security"),
        80 => Some("Internal Error"),
        90 => Some("User Canceled"),
        100 => Some("No Renegotiation"),
        110 => Some("Unsupported Extension"),
        111 => Some("Certificate Unobtainable"),
        112 => Some("Unrecognized Name"),
        113 => Some("Bad Certificate Status Response"),
        114 => Some("Bad Certificate Hash Value"),
        115 => Some("Unknown PSK Identity"),
        _ => None,
    }
}

/// Converts the ssl content type integer type to a more human readable version for events.
pub(crate) fn ssl_content(k: i32) -> Option<&'static str> {
    match k {
        20 => Some("ChangeCipherSpec"),
        21 => Some("Alert"),
        22 => Some("Handshake"),
        23 => Some("ApplicationData"),
        256 => Some("SSL/TLS Header"),
        257 => Some("Inner Content Type"),
        _ => None,
    }
}

/// Converts the ssl handshake message integer type to a more human readable version for events.
pub(crate) fn ssl_handshake(k: i32) -> Option<&'static str> {
    match k {
        0 => Some("HelloRequest"),
        1 => Some("ClientHello"),
        2 => Some("ServerHello"),
        3 => Some("HelloVerifyRequest"),
        4 => Some("NewSessionTicket"),
        5 => Some("EndOfEarlyData"),
        8 => Some("EncryptedExtensions"),
        11 => Some("Certificate"),
        12 => Some("ServerKeyExchange"),
        13 => Some("CertificateRequest"),
        14 => Some("ServerHelloDone"),
        15 => Some("CertificateVerify"),
        16 => Some("ClientKeyExchange"),
        20 => Some("Finished"),
        21 => Some("CertificateUrl"),
        22 => Some("CertificateStatus"),
        23 => Some("SupplementalData"),
        24 => Some("KeyUpdate"),
        67 => Some("NextProto"),
        254 => Some("MessageHash"),
        _ => None,
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use opentelemetry::KeyValue;
    use opentelemetry_api::trace::{Span, TraceContextExt};
    use std::{io::Cursor, os::unix::io::AsRawFd};

    const CONTEXT_STRING: &str = "00-5027c518ca58c8dd07d7f4077173c151-6fffaf4a422e5265-01";

    #[test]
    fn test_context_string_conversion() {
        let c_string: std::ffi::CString = std::ffi::CString::new(CONTEXT_STRING).unwrap();
        let c_string_ptr = c_string.as_ptr();
        let converted_cstring = convert_cstring(c_string_ptr.cast());
        if converted_cstring.is_none() {
            panic!("Unable to convert cstring.")
        }
        assert_eq!(converted_cstring.unwrap(), CONTEXT_STRING)
    }

    #[test]
    fn test_context_extraction() {
        let context: opentelemetry_api::Context = extract_context(CONTEXT_STRING);
        let parent_span = if context.has_active_span() {
            Some(context.span())
        } else {
            None
        };

        if let Some(sc) = parent_span.as_ref().map(|parent| parent.span_context()) {
            assert!("5027c518ca58c8dd07d7f4077173c151" == sc.trace_id().to_string());
            assert!("6fffaf4a422e5265" == sc.span_id().to_string());
        }
    }

    #[test]
    fn test_span_creation() {
        let ctx: opentelemetry_api::Context = extract_context(CONTEXT_STRING);
        let cursor = Cursor::new(Vec::new());
        let mut _span_data = None;
        {
            let exporter = SandwichSpanExporter::new(cursor);
            let mut tracer = SandwichTracer::new(ctx, exporter);
            let _span = tracer.create_span("Test span name");
            tracer
                .current_span
                .as_mut()
                .unwrap()
                .add_event("We did something", vec![KeyValue::new("Key", "Value")]);
            tracer.current_span.as_mut().unwrap().end();
            _span_data = tracer.current_span.as_mut().unwrap().exported_data();
        }
    }
}
