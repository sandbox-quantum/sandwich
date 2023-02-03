// Copyright 2023 SandboxAQ
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        v3.21.5
// source: proto/api/v1/configuration.proto

package v1

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

type Implementation int32

const (
	Implementation_IMPL_UNSPECIFIED      Implementation = 0
	Implementation_IMPL_OPENSSL1_1_1     Implementation = 1
	Implementation_IMPL_OPENSSL1_1_1_OQS Implementation = 2
)

// Enum value maps for Implementation.
var (
	Implementation_name = map[int32]string{
		0: "IMPL_UNSPECIFIED",
		1: "IMPL_OPENSSL1_1_1",
		2: "IMPL_OPENSSL1_1_1_OQS",
	}
	Implementation_value = map[string]int32{
		"IMPL_UNSPECIFIED":      0,
		"IMPL_OPENSSL1_1_1":     1,
		"IMPL_OPENSSL1_1_1_OQS": 2,
	}
)

func (x Implementation) Enum() *Implementation {
	p := new(Implementation)
	*p = x
	return p
}

func (x Implementation) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Implementation) Descriptor() protoreflect.EnumDescriptor {
	return file_proto_api_v1_configuration_proto_enumTypes[0].Descriptor()
}

func (Implementation) Type() protoreflect.EnumType {
	return &file_proto_api_v1_configuration_proto_enumTypes[0]
}

func (x Implementation) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Implementation.Descriptor instead.
func (Implementation) EnumDescriptor() ([]byte, []int) {
	return file_proto_api_v1_configuration_proto_rawDescGZIP(), []int{0}
}

type ClientOptions struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to Opts:
	//	*ClientOptions_Tls
	Opts isClientOptions_Opts `protobuf_oneof:"opts"`
}

func (x *ClientOptions) Reset() {
	*x = ClientOptions{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_api_v1_configuration_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ClientOptions) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ClientOptions) ProtoMessage() {}

func (x *ClientOptions) ProtoReflect() protoreflect.Message {
	mi := &file_proto_api_v1_configuration_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ClientOptions.ProtoReflect.Descriptor instead.
func (*ClientOptions) Descriptor() ([]byte, []int) {
	return file_proto_api_v1_configuration_proto_rawDescGZIP(), []int{0}
}

func (m *ClientOptions) GetOpts() isClientOptions_Opts {
	if m != nil {
		return m.Opts
	}
	return nil
}

func (x *ClientOptions) GetTls() *TLSClientOptions {
	if x, ok := x.GetOpts().(*ClientOptions_Tls); ok {
		return x.Tls
	}
	return nil
}

type isClientOptions_Opts interface {
	isClientOptions_Opts()
}

type ClientOptions_Tls struct {
	Tls *TLSClientOptions `protobuf:"bytes,1,opt,name=tls,proto3,oneof"`
}

func (*ClientOptions_Tls) isClientOptions_Opts() {}

type ServerOptions struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to Opts:
	//	*ServerOptions_Tls
	Opts isServerOptions_Opts `protobuf_oneof:"opts"`
}

func (x *ServerOptions) Reset() {
	*x = ServerOptions{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_api_v1_configuration_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ServerOptions) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ServerOptions) ProtoMessage() {}

func (x *ServerOptions) ProtoReflect() protoreflect.Message {
	mi := &file_proto_api_v1_configuration_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ServerOptions.ProtoReflect.Descriptor instead.
func (*ServerOptions) Descriptor() ([]byte, []int) {
	return file_proto_api_v1_configuration_proto_rawDescGZIP(), []int{1}
}

func (m *ServerOptions) GetOpts() isServerOptions_Opts {
	if m != nil {
		return m.Opts
	}
	return nil
}

func (x *ServerOptions) GetTls() *TLSServerOptions {
	if x, ok := x.GetOpts().(*ServerOptions_Tls); ok {
		return x.Tls
	}
	return nil
}

type isServerOptions_Opts interface {
	isServerOptions_Opts()
}

type ServerOptions_Tls struct {
	Tls *TLSServerOptions `protobuf:"bytes,1,opt,name=tls,proto3,oneof"`
}

func (*ServerOptions_Tls) isServerOptions_Opts() {}

type Configuration struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Impl Implementation `protobuf:"varint,1,opt,name=impl,proto3,enum=saq.sandwich.proto.api.v1.Implementation" json:"impl,omitempty"`
	// Types that are assignable to Opts:
	//	*Configuration_Client
	//	*Configuration_Server
	Opts isConfiguration_Opts `protobuf_oneof:"opts"`
}

func (x *Configuration) Reset() {
	*x = Configuration{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_api_v1_configuration_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Configuration) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Configuration) ProtoMessage() {}

func (x *Configuration) ProtoReflect() protoreflect.Message {
	mi := &file_proto_api_v1_configuration_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Configuration.ProtoReflect.Descriptor instead.
func (*Configuration) Descriptor() ([]byte, []int) {
	return file_proto_api_v1_configuration_proto_rawDescGZIP(), []int{2}
}

func (x *Configuration) GetImpl() Implementation {
	if x != nil {
		return x.Impl
	}
	return Implementation_IMPL_UNSPECIFIED
}

func (m *Configuration) GetOpts() isConfiguration_Opts {
	if m != nil {
		return m.Opts
	}
	return nil
}

func (x *Configuration) GetClient() *ClientOptions {
	if x, ok := x.GetOpts().(*Configuration_Client); ok {
		return x.Client
	}
	return nil
}

func (x *Configuration) GetServer() *ServerOptions {
	if x, ok := x.GetOpts().(*Configuration_Server); ok {
		return x.Server
	}
	return nil
}

type isConfiguration_Opts interface {
	isConfiguration_Opts()
}

type Configuration_Client struct {
	Client *ClientOptions `protobuf:"bytes,2,opt,name=client,proto3,oneof"`
}

type Configuration_Server struct {
	Server *ServerOptions `protobuf:"bytes,3,opt,name=server,proto3,oneof"`
}

func (*Configuration_Client) isConfiguration_Opts() {}

func (*Configuration_Server) isConfiguration_Opts() {}

var File_proto_api_v1_configuration_proto protoreflect.FileDescriptor

var file_proto_api_v1_configuration_proto_rawDesc = []byte{
	0x0a, 0x20, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x76, 0x31, 0x2f, 0x63,
	0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x12, 0x19, 0x73, 0x61, 0x71, 0x2e, 0x73, 0x61, 0x6e, 0x64, 0x77, 0x69, 0x63, 0x68,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x76, 0x31, 0x1a, 0x16, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x76, 0x31, 0x2f, 0x74, 0x6c, 0x73, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x58, 0x0a, 0x0d, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x4f,
	0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x12, 0x3f, 0x0a, 0x03, 0x74, 0x6c, 0x73, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x2b, 0x2e, 0x73, 0x61, 0x71, 0x2e, 0x73, 0x61, 0x6e, 0x64, 0x77, 0x69,
	0x63, 0x68, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x76, 0x31, 0x2e,
	0x54, 0x4c, 0x53, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73,
	0x48, 0x00, 0x52, 0x03, 0x74, 0x6c, 0x73, 0x42, 0x06, 0x0a, 0x04, 0x6f, 0x70, 0x74, 0x73, 0x22,
	0x58, 0x0a, 0x0d, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73,
	0x12, 0x3f, 0x0a, 0x03, 0x74, 0x6c, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2b, 0x2e,
	0x73, 0x61, 0x71, 0x2e, 0x73, 0x61, 0x6e, 0x64, 0x77, 0x69, 0x63, 0x68, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x76, 0x31, 0x2e, 0x54, 0x4c, 0x53, 0x53, 0x65, 0x72,
	0x76, 0x65, 0x72, 0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x48, 0x00, 0x52, 0x03, 0x74, 0x6c,
	0x73, 0x42, 0x06, 0x0a, 0x04, 0x6f, 0x70, 0x74, 0x73, 0x22, 0xde, 0x01, 0x0a, 0x0d, 0x43, 0x6f,
	0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x3d, 0x0a, 0x04, 0x69,
	0x6d, 0x70, 0x6c, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x29, 0x2e, 0x73, 0x61, 0x71, 0x2e,
	0x73, 0x61, 0x6e, 0x64, 0x77, 0x69, 0x63, 0x68, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x61,
	0x70, 0x69, 0x2e, 0x76, 0x31, 0x2e, 0x49, 0x6d, 0x70, 0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x52, 0x04, 0x69, 0x6d, 0x70, 0x6c, 0x12, 0x42, 0x0a, 0x06, 0x63, 0x6c,
	0x69, 0x65, 0x6e, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x28, 0x2e, 0x73, 0x61, 0x71,
	0x2e, 0x73, 0x61, 0x6e, 0x64, 0x77, 0x69, 0x63, 0x68, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e,
	0x61, 0x70, 0x69, 0x2e, 0x76, 0x31, 0x2e, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x4f, 0x70, 0x74,
	0x69, 0x6f, 0x6e, 0x73, 0x48, 0x00, 0x52, 0x06, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x12, 0x42,
	0x0a, 0x06, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x28,
	0x2e, 0x73, 0x61, 0x71, 0x2e, 0x73, 0x61, 0x6e, 0x64, 0x77, 0x69, 0x63, 0x68, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x76, 0x31, 0x2e, 0x53, 0x65, 0x72, 0x76, 0x65,
	0x72, 0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x48, 0x00, 0x52, 0x06, 0x73, 0x65, 0x72, 0x76,
	0x65, 0x72, 0x42, 0x06, 0x0a, 0x04, 0x6f, 0x70, 0x74, 0x73, 0x2a, 0x58, 0x0a, 0x0e, 0x49, 0x6d,
	0x70, 0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x14, 0x0a, 0x10,
	0x49, 0x4d, 0x50, 0x4c, 0x5f, 0x55, 0x4e, 0x53, 0x50, 0x45, 0x43, 0x49, 0x46, 0x49, 0x45, 0x44,
	0x10, 0x00, 0x12, 0x15, 0x0a, 0x11, 0x49, 0x4d, 0x50, 0x4c, 0x5f, 0x4f, 0x50, 0x45, 0x4e, 0x53,
	0x53, 0x4c, 0x31, 0x5f, 0x31, 0x5f, 0x31, 0x10, 0x01, 0x12, 0x19, 0x0a, 0x15, 0x49, 0x4d, 0x50,
	0x4c, 0x5f, 0x4f, 0x50, 0x45, 0x4e, 0x53, 0x53, 0x4c, 0x31, 0x5f, 0x31, 0x5f, 0x31, 0x5f, 0x4f,
	0x51, 0x53, 0x10, 0x02, 0x42, 0x3e, 0x5a, 0x3c, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63,
	0x6f, 0x6d, 0x2f, 0x73, 0x61, 0x6e, 0x64, 0x62, 0x6f, 0x78, 0x2d, 0x71, 0x75, 0x61, 0x6e, 0x74,
	0x75, 0x6d, 0x2f, 0x73, 0x61, 0x6e, 0x64, 0x77, 0x69, 0x63, 0x68, 0x2f, 0x67, 0x6f, 0x2f, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x73, 0x61, 0x6e, 0x64, 0x77, 0x69, 0x63, 0x68, 0x2f, 0x61, 0x70,
	0x69, 0x2f, 0x76, 0x31, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_proto_api_v1_configuration_proto_rawDescOnce sync.Once
	file_proto_api_v1_configuration_proto_rawDescData = file_proto_api_v1_configuration_proto_rawDesc
)

func file_proto_api_v1_configuration_proto_rawDescGZIP() []byte {
	file_proto_api_v1_configuration_proto_rawDescOnce.Do(func() {
		file_proto_api_v1_configuration_proto_rawDescData = protoimpl.X.CompressGZIP(file_proto_api_v1_configuration_proto_rawDescData)
	})
	return file_proto_api_v1_configuration_proto_rawDescData
}

var file_proto_api_v1_configuration_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_proto_api_v1_configuration_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_proto_api_v1_configuration_proto_goTypes = []interface{}{
	(Implementation)(0),      // 0: saq.sandwich.proto.api.v1.Implementation
	(*ClientOptions)(nil),    // 1: saq.sandwich.proto.api.v1.ClientOptions
	(*ServerOptions)(nil),    // 2: saq.sandwich.proto.api.v1.ServerOptions
	(*Configuration)(nil),    // 3: saq.sandwich.proto.api.v1.Configuration
	(*TLSClientOptions)(nil), // 4: saq.sandwich.proto.api.v1.TLSClientOptions
	(*TLSServerOptions)(nil), // 5: saq.sandwich.proto.api.v1.TLSServerOptions
}
var file_proto_api_v1_configuration_proto_depIdxs = []int32{
	4, // 0: saq.sandwich.proto.api.v1.ClientOptions.tls:type_name -> saq.sandwich.proto.api.v1.TLSClientOptions
	5, // 1: saq.sandwich.proto.api.v1.ServerOptions.tls:type_name -> saq.sandwich.proto.api.v1.TLSServerOptions
	0, // 2: saq.sandwich.proto.api.v1.Configuration.impl:type_name -> saq.sandwich.proto.api.v1.Implementation
	1, // 3: saq.sandwich.proto.api.v1.Configuration.client:type_name -> saq.sandwich.proto.api.v1.ClientOptions
	2, // 4: saq.sandwich.proto.api.v1.Configuration.server:type_name -> saq.sandwich.proto.api.v1.ServerOptions
	5, // [5:5] is the sub-list for method output_type
	5, // [5:5] is the sub-list for method input_type
	5, // [5:5] is the sub-list for extension type_name
	5, // [5:5] is the sub-list for extension extendee
	0, // [0:5] is the sub-list for field type_name
}

func init() { file_proto_api_v1_configuration_proto_init() }
func file_proto_api_v1_configuration_proto_init() {
	if File_proto_api_v1_configuration_proto != nil {
		return
	}
	file_proto_api_v1_tls_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_proto_api_v1_configuration_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ClientOptions); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_proto_api_v1_configuration_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ServerOptions); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_proto_api_v1_configuration_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Configuration); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	file_proto_api_v1_configuration_proto_msgTypes[0].OneofWrappers = []interface{}{
		(*ClientOptions_Tls)(nil),
	}
	file_proto_api_v1_configuration_proto_msgTypes[1].OneofWrappers = []interface{}{
		(*ServerOptions_Tls)(nil),
	}
	file_proto_api_v1_configuration_proto_msgTypes[2].OneofWrappers = []interface{}{
		(*Configuration_Client)(nil),
		(*Configuration_Server)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_proto_api_v1_configuration_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_proto_api_v1_configuration_proto_goTypes,
		DependencyIndexes: file_proto_api_v1_configuration_proto_depIdxs,
		EnumInfos:         file_proto_api_v1_configuration_proto_enumTypes,
		MessageInfos:      file_proto_api_v1_configuration_proto_msgTypes,
	}.Build()
	File_proto_api_v1_configuration_proto = out.File
	file_proto_api_v1_configuration_proto_rawDesc = nil
	file_proto_api_v1_configuration_proto_goTypes = nil
	file_proto_api_v1_configuration_proto_depIdxs = nil
}
