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
// 	protoc        v3.21.7
// source: proto/io.proto

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

type IOError int32

const (
	IOError_IOERROR_OK          IOError = 0
	IOError_IOERROR_IN_PROGRESS IOError = 1
	IOError_IOERROR_WOULD_BLOCK IOError = 2
	IOError_IOERROR_REFUSED     IOError = 3
	IOError_IOERROR_CLOSED      IOError = 4
	IOError_IOERROR_INVALID     IOError = 5
	IOError_IOERROR_UNKNOWN     IOError = 6
)

// Enum value maps for IOError.
var (
	IOError_name = map[int32]string{
		0: "IOERROR_OK",
		1: "IOERROR_IN_PROGRESS",
		2: "IOERROR_WOULD_BLOCK",
		3: "IOERROR_REFUSED",
		4: "IOERROR_CLOSED",
		5: "IOERROR_INVALID",
		6: "IOERROR_UNKNOWN",
	}
	IOError_value = map[string]int32{
		"IOERROR_OK":          0,
		"IOERROR_IN_PROGRESS": 1,
		"IOERROR_WOULD_BLOCK": 2,
		"IOERROR_REFUSED":     3,
		"IOERROR_CLOSED":      4,
		"IOERROR_INVALID":     5,
		"IOERROR_UNKNOWN":     6,
	}
)

func (x IOError) Enum() *IOError {
	p := new(IOError)
	*p = x
	return p
}

func (x IOError) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (IOError) Descriptor() protoreflect.EnumDescriptor {
	return file_saq_pqc_sandwich_proto_io_proto_enumTypes[0].Descriptor()
}

func (IOError) Type() protoreflect.EnumType {
	return &file_saq_pqc_sandwich_proto_io_proto_enumTypes[0]
}

func (x IOError) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use IOError.Descriptor instead.
func (IOError) EnumDescriptor() ([]byte, []int) {
	return file_saq_pqc_sandwich_proto_io_proto_rawDescGZIP(), []int{0}
}

var File_saq_pqc_sandwich_proto_io_proto protoreflect.FileDescriptor

var file_saq_pqc_sandwich_proto_io_proto_rawDesc = []byte{
	0x0a, 0x1f, 0x73, 0x61, 0x71, 0x2f, 0x70, 0x71, 0x63, 0x2f, 0x73, 0x61, 0x6e, 0x64, 0x77, 0x69,
	0x63, 0x68, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x69, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x12, 0x19, 0x73, 0x61, 0x71, 0x2e, 0x70, 0x71, 0x63, 0x2e, 0x73, 0x61, 0x6e, 0x64, 0x77,
	0x69, 0x63, 0x68, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x69, 0x6f, 0x2a, 0x9e, 0x01, 0x0a,
	0x07, 0x49, 0x4f, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x12, 0x0e, 0x0a, 0x0a, 0x49, 0x4f, 0x45, 0x52,
	0x52, 0x4f, 0x52, 0x5f, 0x4f, 0x4b, 0x10, 0x00, 0x12, 0x17, 0x0a, 0x13, 0x49, 0x4f, 0x45, 0x52,
	0x52, 0x4f, 0x52, 0x5f, 0x49, 0x4e, 0x5f, 0x50, 0x52, 0x4f, 0x47, 0x52, 0x45, 0x53, 0x53, 0x10,
	0x01, 0x12, 0x17, 0x0a, 0x13, 0x49, 0x4f, 0x45, 0x52, 0x52, 0x4f, 0x52, 0x5f, 0x57, 0x4f, 0x55,
	0x4c, 0x44, 0x5f, 0x42, 0x4c, 0x4f, 0x43, 0x4b, 0x10, 0x02, 0x12, 0x13, 0x0a, 0x0f, 0x49, 0x4f,
	0x45, 0x52, 0x52, 0x4f, 0x52, 0x5f, 0x52, 0x45, 0x46, 0x55, 0x53, 0x45, 0x44, 0x10, 0x03, 0x12,
	0x12, 0x0a, 0x0e, 0x49, 0x4f, 0x45, 0x52, 0x52, 0x4f, 0x52, 0x5f, 0x43, 0x4c, 0x4f, 0x53, 0x45,
	0x44, 0x10, 0x04, 0x12, 0x13, 0x0a, 0x0f, 0x49, 0x4f, 0x45, 0x52, 0x52, 0x4f, 0x52, 0x5f, 0x49,
	0x4e, 0x56, 0x41, 0x4c, 0x49, 0x44, 0x10, 0x05, 0x12, 0x13, 0x0a, 0x0f, 0x49, 0x4f, 0x45, 0x52,
	0x52, 0x4f, 0x52, 0x5f, 0x55, 0x4e, 0x4b, 0x4e, 0x4f, 0x57, 0x4e, 0x10, 0x06, 0x42, 0x47, 0x5a,
	0x45, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x73, 0x61, 0x6e, 0x64,
	0x62, 0x6f, 0x78, 0x2d, 0x71, 0x75, 0x61, 0x6e, 0x74, 0x75, 0x6d, 0x2f, 0x63, 0x68, 0x75, 0x6e,
	0x67, 0x75, 0x73, 0x2f, 0x73, 0x61, 0x71, 0x2f, 0x70, 0x71, 0x63, 0x2f, 0x73, 0x61, 0x6e, 0x64,
	0x77, 0x69, 0x63, 0x68, 0x2f, 0x67, 0x6f, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x73, 0x61,
	0x6e, 0x64, 0x77, 0x69, 0x63, 0x68, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_saq_pqc_sandwich_proto_io_proto_rawDescOnce sync.Once
	file_saq_pqc_sandwich_proto_io_proto_rawDescData = file_saq_pqc_sandwich_proto_io_proto_rawDesc
)

func file_saq_pqc_sandwich_proto_io_proto_rawDescGZIP() []byte {
	file_saq_pqc_sandwich_proto_io_proto_rawDescOnce.Do(func() {
		file_saq_pqc_sandwich_proto_io_proto_rawDescData = protoimpl.X.CompressGZIP(file_saq_pqc_sandwich_proto_io_proto_rawDescData)
	})
	return file_saq_pqc_sandwich_proto_io_proto_rawDescData
}

var file_saq_pqc_sandwich_proto_io_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_saq_pqc_sandwich_proto_io_proto_goTypes = []interface{}{
	(IOError)(0), // 0: saq.sandwich.proto.io.IOError
}
var file_saq_pqc_sandwich_proto_io_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_saq_pqc_sandwich_proto_io_proto_init() }
func file_saq_pqc_sandwich_proto_io_proto_init() {
	if File_saq_pqc_sandwich_proto_io_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_saq_pqc_sandwich_proto_io_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   0,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_saq_pqc_sandwich_proto_io_proto_goTypes,
		DependencyIndexes: file_saq_pqc_sandwich_proto_io_proto_depIdxs,
		EnumInfos:         file_saq_pqc_sandwich_proto_io_proto_enumTypes,
	}.Build()
	File_saq_pqc_sandwich_proto_io_proto = out.File
	file_saq_pqc_sandwich_proto_io_proto_rawDesc = nil
	file_saq_pqc_sandwich_proto_io_proto_goTypes = nil
	file_saq_pqc_sandwich_proto_io_proto_depIdxs = nil
}
