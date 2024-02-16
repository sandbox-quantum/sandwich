// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

package sandwich

import (
	"context"
	"os"
	"time"

	"encoding/binary"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	otcommonpb "go.opentelemetry.io/proto/otlp/common/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"
)

// This has all of the data needed to pass to the Rust FFI, propagate context, and deserialize spans.
type SandwichTracer struct {
	tracer         trace.Tracer
	read_buf_fd    *os.File
	write_buf_fd   int32
	carrier        propagation.MapCarrier
	context_string string
	ctx            context.Context
}

// This is all of the interesting information we care about from a span in Rust.
type SandwichSpan struct {
	Name       string
	Context    trace.SpanContext
	Events     []sdktrace.Event
	Attributes []attribute.KeyValue
	Start_time int64
	End_time   int64
}

func NewSandwichTracer(ctx context.Context, tracer trace.Tracer) *SandwichTracer {
	/// ctx:    Context originated from an existing span. If provided a blank context, the spans in rust
	///         won't be assigned the same trace ID.
	/// tracer: We need to get the tracer so we can recreate the spans from rust in Go. This differs from
	///         Python because the otel go library doesn't provide the same api.

	propogator := propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{})

	carrier := propagation.MapCarrier{}

	propogator.Inject(ctx, carrier)

	context_string := carrier.Get("traceparent")

	r, w, _ := os.Pipe()

	return &SandwichTracer{
		tracer:         tracer,
		read_buf_fd:    r,
		write_buf_fd:   int32(w.Fd()),
		carrier:        carrier,
		context_string: context_string,
		ctx:            ctx,
	}
}

// This is the function that we should call to "flush" the buffer. This will deserialize and
// export the span from rust.
func (self SandwichTracer) export_span_buffer() {
	for {
		message_length := self.get_message_length()
		if message_length == 0 {
			break
		}
		span_data := make([]byte, message_length)
		bytes_read, err := self.read_buf_fd.Read(span_data)
		if bytes_read == 0 || err != nil {
			return
		}
		span_proto := new(tracepb.Span)
		if err := proto.Unmarshal(span_data, span_proto); err != nil {
			return
		}
		self.export_span(convert_pbspan(span_proto))
	}
}

// Each span is prepended with a 4 byte length, as spans are variable in size.
func (self SandwichTracer) get_message_length() int {
	message_length_bytes := make([]byte, 4)
	bytes_read, err := self.read_buf_fd.Read(message_length_bytes)
	if bytes_read == 0 || err != nil {
		return 0
	}
	message_length := binary.LittleEndian.Uint32(message_length_bytes)
	return int(message_length)
}

// This recreates spans as golang spans with the data recieved from rust.
func (self SandwichTracer) export_span(s SandwichSpan) {
	_, span := self.tracer.Start(self.ctx, s.Name, trace.WithTimestamp(time.Unix(0, s.Start_time)))
	span.SetAttributes(s.Attributes...)
	for _, event := range s.Events {
		span.AddEvent(event.Name, trace.WithTimestamp(event.Time), trace.WithAttributes(event.Attributes...))
	}
	span.End(trace.WithTimestamp(time.Unix(0, s.End_time)))
}

// Converts the protobuf object into a SandwichSpan. SandwichSpan uses the same object types
// that the otel library is expecting the information to be in.
func convert_pbspan(pbspan *tracepb.Span) SandwichSpan {
	// Go 1.18 workaround -- Gone in 1.20
	trace_array := [16]byte{}
	span_array := [8]byte{}
	copy(trace_array[:], pbspan.TraceId)
	copy(span_array[:], pbspan.SpanId)

	ctx_cfg := trace.SpanContextConfig{
		TraceID:    trace.TraceID(trace_array),
		SpanID:     trace.SpanID(span_array),
		TraceFlags: trace.FlagsSampled,
		Remote:     true,
		TraceState: trace.TraceState{},
	}
	ctx := trace.NewSpanContext(ctx_cfg)
	events := make([]sdktrace.Event, len(pbspan.Events))
	for i, event := range pbspan.Events {
		event_attributes := make([]attribute.KeyValue, len(event.Attributes))

		for y, protoKV := range event.Attributes {
			event_attributes[y] = convert_attribute_keyvalue(protoKV)
		}

		events[i] = sdktrace.Event{
			Name:                  pbspan.Events[i].Name,
			Time:                  time.Unix(0, int64(pbspan.Events[i].TimeUnixNano)),
			Attributes:            event_attributes,
			DroppedAttributeCount: 0,
		}
	}

	span_attributes := make([]attribute.KeyValue, len(pbspan.Attributes))

	for i, protoKV := range pbspan.Attributes {
		span_attributes[i] = convert_attribute_keyvalue(protoKV)
	}

	return SandwichSpan{
		Name:       pbspan.Name,
		Context:    ctx,
		Events:     events,
		Attributes: span_attributes,
		Start_time: int64(pbspan.StartTimeUnixNano),
		End_time:   int64(pbspan.EndTimeUnixNano),
	}
}

// For now, we just convert strings and integers. If we want to convert more in the future,
// This is extensible.
func convert_attribute_keyvalue(protoKV *otcommonpb.KeyValue) attribute.KeyValue {
	attrKV := attribute.KeyValue{
		Key: attribute.Key(protoKV.Key),
	}
	switch val := protoKV.Value.Value.(type) {
	case *otcommonpb.AnyValue_StringValue:
		attrKV.Value = attribute.StringValue(val.StringValue)
	case *otcommonpb.AnyValue_IntValue:
		attrKV.Value = attribute.IntValue(int(val.IntValue))
	default:
		return attribute.KeyValue{}
	}
	return attrKV
}
