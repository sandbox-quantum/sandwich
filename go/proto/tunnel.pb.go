// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        v3.21.7
// source: proto/tunnel.proto

package sandwich

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type State int32

const (
	State_STATE_NOT_CONNECTED          State = 0
	State_STATE_CONNECTION_IN_PROGRESS State = 1
	State_STATE_HANDSHAKE_IN_PROGRESS  State = 2
	State_STATE_HANDSHAKE_DONE         State = 3
	State_STATE_BEING_SHUTDOWN         State = 4
	State_STATE_DISCONNECTED           State = 5
	State_STATE_ERROR                  State = 6
)

// Enum value maps for State.
var (
	State_name = map[int32]string{
		0: "STATE_NOT_CONNECTED",
		1: "STATE_CONNECTION_IN_PROGRESS",
		2: "STATE_HANDSHAKE_IN_PROGRESS",
		3: "STATE_HANDSHAKE_DONE",
		4: "STATE_BEING_SHUTDOWN",
		5: "STATE_DISCONNECTED",
		6: "STATE_ERROR",
	}
	State_value = map[string]int32{
		"STATE_NOT_CONNECTED":          0,
		"STATE_CONNECTION_IN_PROGRESS": 1,
		"STATE_HANDSHAKE_IN_PROGRESS":  2,
		"STATE_HANDSHAKE_DONE":         3,
		"STATE_BEING_SHUTDOWN":         4,
		"STATE_DISCONNECTED":           5,
		"STATE_ERROR":                  6,
	}
)

func (x State) Enum() *State {
	p := new(State)
	*p = x
	return p
}

func (x State) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (State) Descriptor() protoreflect.EnumDescriptor {
	return file_saq_pqc_sandwich_proto_tunnel_proto_enumTypes[0].Descriptor()
}

func (State) Type() protoreflect.EnumType {
	return &file_saq_pqc_sandwich_proto_tunnel_proto_enumTypes[0]
}

func (x State) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use State.Descriptor instead.
func (State) EnumDescriptor() ([]byte, []int) {
	return file_saq_pqc_sandwich_proto_tunnel_proto_rawDescGZIP(), []int{0}
}

type HandshakeState int32

const (
	HandshakeState_HANDSHAKESTATE_IN_PROGRESS HandshakeState = 0
	HandshakeState_HANDSHAKESTATE_DONE        HandshakeState = 1
	HandshakeState_HANDSHAKESTATE_WANT_READ   HandshakeState = 2
	HandshakeState_HANDSHAKESTATE_WANT_WRITE  HandshakeState = 3
	HandshakeState_HANDSHAKESTATE_ERROR       HandshakeState = 4
)

// Enum value maps for HandshakeState.
var (
	HandshakeState_name = map[int32]string{
		0: "HANDSHAKESTATE_IN_PROGRESS",
		1: "HANDSHAKESTATE_DONE",
		2: "HANDSHAKESTATE_WANT_READ",
		3: "HANDSHAKESTATE_WANT_WRITE",
		4: "HANDSHAKESTATE_ERROR",
	}
	HandshakeState_value = map[string]int32{
		"HANDSHAKESTATE_IN_PROGRESS": 0,
		"HANDSHAKESTATE_DONE":        1,
		"HANDSHAKESTATE_WANT_READ":   2,
		"HANDSHAKESTATE_WANT_WRITE":  3,
		"HANDSHAKESTATE_ERROR":       4,
	}
)

func (x HandshakeState) Enum() *HandshakeState {
	p := new(HandshakeState)
	*p = x
	return p
}

func (x HandshakeState) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (HandshakeState) Descriptor() protoreflect.EnumDescriptor {
	return file_saq_pqc_sandwich_proto_tunnel_proto_enumTypes[1].Descriptor()
}

func (HandshakeState) Type() protoreflect.EnumType {
	return &file_saq_pqc_sandwich_proto_tunnel_proto_enumTypes[1]
}

func (x HandshakeState) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use HandshakeState.Descriptor instead.
func (HandshakeState) EnumDescriptor() ([]byte, []int) {
	return file_saq_pqc_sandwich_proto_tunnel_proto_rawDescGZIP(), []int{1}
}

type RecordError int32

const (
	RecordError_RECORDERROR_OK             RecordError = 0
	RecordError_RECORDERROR_WANT_READ      RecordError = 1
	RecordError_RECORDERROR_WANT_WRITE     RecordError = 2
	RecordError_RECORDERROR_BEING_SHUTDOWN RecordError = 3
	RecordError_RECORDERROR_CLOSED         RecordError = 4
	RecordError_RECORDERROR_UNKNOWN        RecordError = 5
)

// Enum value maps for RecordError.
var (
	RecordError_name = map[int32]string{
		0: "RECORDERROR_OK",
		1: "RECORDERROR_WANT_READ",
		2: "RECORDERROR_WANT_WRITE",
		3: "RECORDERROR_BEING_SHUTDOWN",
		4: "RECORDERROR_CLOSED",
		5: "RECORDERROR_UNKNOWN",
	}
	RecordError_value = map[string]int32{
		"RECORDERROR_OK":             0,
		"RECORDERROR_WANT_READ":      1,
		"RECORDERROR_WANT_WRITE":     2,
		"RECORDERROR_BEING_SHUTDOWN": 3,
		"RECORDERROR_CLOSED":         4,
		"RECORDERROR_UNKNOWN":        5,
	}
)

func (x RecordError) Enum() *RecordError {
	p := new(RecordError)
	*p = x
	return p
}

func (x RecordError) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (RecordError) Descriptor() protoreflect.EnumDescriptor {
	return file_saq_pqc_sandwich_proto_tunnel_proto_enumTypes[2].Descriptor()
}

func (RecordError) Type() protoreflect.EnumType {
	return &file_saq_pqc_sandwich_proto_tunnel_proto_enumTypes[2]
}

func (x RecordError) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use RecordError.Descriptor instead.
func (RecordError) EnumDescriptor() ([]byte, []int) {
	return file_saq_pqc_sandwich_proto_tunnel_proto_rawDescGZIP(), []int{2}
}

var File_saq_pqc_sandwich_proto_tunnel_proto protoreflect.FileDescriptor

var file_saq_pqc_sandwich_proto_tunnel_proto_rawDesc = []byte{
	0x0a, 0x23, 0x73, 0x61, 0x71, 0x2f, 0x70, 0x71, 0x63, 0x2f, 0x73, 0x61, 0x6e, 0x64, 0x77, 0x69,
	0x63, 0x68, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x74, 0x75, 0x6e, 0x6e, 0x65, 0x6c, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x1d, 0x73, 0x61, 0x71, 0x2e, 0x70, 0x71, 0x63, 0x2e, 0x73,
	0x61, 0x6e, 0x64, 0x77, 0x69, 0x63, 0x68, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x74, 0x75,
	0x6e, 0x6e, 0x65, 0x6c, 0x2a, 0xc0, 0x01, 0x0a, 0x05, 0x53, 0x74, 0x61, 0x74, 0x65, 0x12, 0x17,
	0x0a, 0x13, 0x53, 0x54, 0x41, 0x54, 0x45, 0x5f, 0x4e, 0x4f, 0x54, 0x5f, 0x43, 0x4f, 0x4e, 0x4e,
	0x45, 0x43, 0x54, 0x45, 0x44, 0x10, 0x00, 0x12, 0x20, 0x0a, 0x1c, 0x53, 0x54, 0x41, 0x54, 0x45,
	0x5f, 0x43, 0x4f, 0x4e, 0x4e, 0x45, 0x43, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x49, 0x4e, 0x5f, 0x50,
	0x52, 0x4f, 0x47, 0x52, 0x45, 0x53, 0x53, 0x10, 0x01, 0x12, 0x1f, 0x0a, 0x1b, 0x53, 0x54, 0x41,
	0x54, 0x45, 0x5f, 0x48, 0x41, 0x4e, 0x44, 0x53, 0x48, 0x41, 0x4b, 0x45, 0x5f, 0x49, 0x4e, 0x5f,
	0x50, 0x52, 0x4f, 0x47, 0x52, 0x45, 0x53, 0x53, 0x10, 0x02, 0x12, 0x18, 0x0a, 0x14, 0x53, 0x54,
	0x41, 0x54, 0x45, 0x5f, 0x48, 0x41, 0x4e, 0x44, 0x53, 0x48, 0x41, 0x4b, 0x45, 0x5f, 0x44, 0x4f,
	0x4e, 0x45, 0x10, 0x03, 0x12, 0x18, 0x0a, 0x14, 0x53, 0x54, 0x41, 0x54, 0x45, 0x5f, 0x42, 0x45,
	0x49, 0x4e, 0x47, 0x5f, 0x53, 0x48, 0x55, 0x54, 0x44, 0x4f, 0x57, 0x4e, 0x10, 0x04, 0x12, 0x16,
	0x0a, 0x12, 0x53, 0x54, 0x41, 0x54, 0x45, 0x5f, 0x44, 0x49, 0x53, 0x43, 0x4f, 0x4e, 0x4e, 0x45,
	0x43, 0x54, 0x45, 0x44, 0x10, 0x05, 0x12, 0x0f, 0x0a, 0x0b, 0x53, 0x54, 0x41, 0x54, 0x45, 0x5f,
	0x45, 0x52, 0x52, 0x4f, 0x52, 0x10, 0x06, 0x2a, 0xa0, 0x01, 0x0a, 0x0e, 0x48, 0x61, 0x6e, 0x64,
	0x73, 0x68, 0x61, 0x6b, 0x65, 0x53, 0x74, 0x61, 0x74, 0x65, 0x12, 0x1e, 0x0a, 0x1a, 0x48, 0x41,
	0x4e, 0x44, 0x53, 0x48, 0x41, 0x4b, 0x45, 0x53, 0x54, 0x41, 0x54, 0x45, 0x5f, 0x49, 0x4e, 0x5f,
	0x50, 0x52, 0x4f, 0x47, 0x52, 0x45, 0x53, 0x53, 0x10, 0x00, 0x12, 0x17, 0x0a, 0x13, 0x48, 0x41,
	0x4e, 0x44, 0x53, 0x48, 0x41, 0x4b, 0x45, 0x53, 0x54, 0x41, 0x54, 0x45, 0x5f, 0x44, 0x4f, 0x4e,
	0x45, 0x10, 0x01, 0x12, 0x1c, 0x0a, 0x18, 0x48, 0x41, 0x4e, 0x44, 0x53, 0x48, 0x41, 0x4b, 0x45,
	0x53, 0x54, 0x41, 0x54, 0x45, 0x5f, 0x57, 0x41, 0x4e, 0x54, 0x5f, 0x52, 0x45, 0x41, 0x44, 0x10,
	0x02, 0x12, 0x1d, 0x0a, 0x19, 0x48, 0x41, 0x4e, 0x44, 0x53, 0x48, 0x41, 0x4b, 0x45, 0x53, 0x54,
	0x41, 0x54, 0x45, 0x5f, 0x57, 0x41, 0x4e, 0x54, 0x5f, 0x57, 0x52, 0x49, 0x54, 0x45, 0x10, 0x03,
	0x12, 0x18, 0x0a, 0x14, 0x48, 0x41, 0x4e, 0x44, 0x53, 0x48, 0x41, 0x4b, 0x45, 0x53, 0x54, 0x41,
	0x54, 0x45, 0x5f, 0x45, 0x52, 0x52, 0x4f, 0x52, 0x10, 0x04, 0x2a, 0xa9, 0x01, 0x0a, 0x0b, 0x52,
	0x65, 0x63, 0x6f, 0x72, 0x64, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x12, 0x12, 0x0a, 0x0e, 0x52, 0x45,
	0x43, 0x4f, 0x52, 0x44, 0x45, 0x52, 0x52, 0x4f, 0x52, 0x5f, 0x4f, 0x4b, 0x10, 0x00, 0x12, 0x19,
	0x0a, 0x15, 0x52, 0x45, 0x43, 0x4f, 0x52, 0x44, 0x45, 0x52, 0x52, 0x4f, 0x52, 0x5f, 0x57, 0x41,
	0x4e, 0x54, 0x5f, 0x52, 0x45, 0x41, 0x44, 0x10, 0x01, 0x12, 0x1a, 0x0a, 0x16, 0x52, 0x45, 0x43,
	0x4f, 0x52, 0x44, 0x45, 0x52, 0x52, 0x4f, 0x52, 0x5f, 0x57, 0x41, 0x4e, 0x54, 0x5f, 0x57, 0x52,
	0x49, 0x54, 0x45, 0x10, 0x02, 0x12, 0x1e, 0x0a, 0x1a, 0x52, 0x45, 0x43, 0x4f, 0x52, 0x44, 0x45,
	0x52, 0x52, 0x4f, 0x52, 0x5f, 0x42, 0x45, 0x49, 0x4e, 0x47, 0x5f, 0x53, 0x48, 0x55, 0x54, 0x44,
	0x4f, 0x57, 0x4e, 0x10, 0x03, 0x12, 0x16, 0x0a, 0x12, 0x52, 0x45, 0x43, 0x4f, 0x52, 0x44, 0x45,
	0x52, 0x52, 0x4f, 0x52, 0x5f, 0x43, 0x4c, 0x4f, 0x53, 0x45, 0x44, 0x10, 0x04, 0x12, 0x17, 0x0a,
	0x13, 0x52, 0x45, 0x43, 0x4f, 0x52, 0x44, 0x45, 0x52, 0x52, 0x4f, 0x52, 0x5f, 0x55, 0x4e, 0x4b,
	0x4e, 0x4f, 0x57, 0x4e, 0x10, 0x05, 0x42, 0x47, 0x5a, 0x45, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62,
	0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x73, 0x61, 0x6e, 0x64, 0x62, 0x6f, 0x78, 0x2d, 0x71, 0x75, 0x61,
	0x6e, 0x74, 0x75, 0x6d, 0x2f, 0x63, 0x68, 0x75, 0x6e, 0x67, 0x75, 0x73, 0x2f, 0x73, 0x61, 0x71,
	0x2f, 0x70, 0x71, 0x63, 0x2f, 0x73, 0x61, 0x6e, 0x64, 0x77, 0x69, 0x63, 0x68, 0x2f, 0x67, 0x6f,
	0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x73, 0x61, 0x6e, 0x64, 0x77, 0x69, 0x63, 0x68, 0x62,
	0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_saq_pqc_sandwich_proto_tunnel_proto_rawDescOnce sync.Once
	file_saq_pqc_sandwich_proto_tunnel_proto_rawDescData = file_saq_pqc_sandwich_proto_tunnel_proto_rawDesc
)

func file_saq_pqc_sandwich_proto_tunnel_proto_rawDescGZIP() []byte {
	file_saq_pqc_sandwich_proto_tunnel_proto_rawDescOnce.Do(func() {
		file_saq_pqc_sandwich_proto_tunnel_proto_rawDescData = protoimpl.X.CompressGZIP(file_saq_pqc_sandwich_proto_tunnel_proto_rawDescData)
	})
	return file_saq_pqc_sandwich_proto_tunnel_proto_rawDescData
}

var file_saq_pqc_sandwich_proto_tunnel_proto_enumTypes = make([]protoimpl.EnumInfo, 3)
var file_saq_pqc_sandwich_proto_tunnel_proto_goTypes = []interface{}{
	(State)(0),          // 0: saq.sandwich.proto.tunnel.State
	(HandshakeState)(0), // 1: saq.sandwich.proto.tunnel.HandshakeState
	(RecordError)(0),    // 2: saq.sandwich.proto.tunnel.RecordError
}
var file_saq_pqc_sandwich_proto_tunnel_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_saq_pqc_sandwich_proto_tunnel_proto_init() }
func file_saq_pqc_sandwich_proto_tunnel_proto_init() {
	if File_saq_pqc_sandwich_proto_tunnel_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_saq_pqc_sandwich_proto_tunnel_proto_rawDesc,
			NumEnums:      3,
			NumMessages:   0,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_saq_pqc_sandwich_proto_tunnel_proto_goTypes,
		DependencyIndexes: file_saq_pqc_sandwich_proto_tunnel_proto_depIdxs,
		EnumInfos:         file_saq_pqc_sandwich_proto_tunnel_proto_enumTypes,
	}.Build()
	File_saq_pqc_sandwich_proto_tunnel_proto = out.File
	file_saq_pqc_sandwich_proto_tunnel_proto_rawDesc = nil
	file_saq_pqc_sandwich_proto_tunnel_proto_goTypes = nil
	file_saq_pqc_sandwich_proto_tunnel_proto_depIdxs = nil
}
