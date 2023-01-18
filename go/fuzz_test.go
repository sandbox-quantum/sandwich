// Copyright 2022 SandboxAQ
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

package sandwich_test

import (
	"encoding/base64"
	"log"
	"testing"

	"github.com/sandbox-quantum/sandwich/go/sandwich"
	"google.golang.org/protobuf/proto"

	api "github.com/sandbox-quantum/sandwich/go/proto/sandwich/api/v1"
)

func TestFuzzCases(t *testing.T) {
	// The following test cases were found with fuzzing.
	tests := []struct {
		payload     string
		wantSuccess bool
	}{
		{
			payload: "CCs=",
		},
		{
			payload: "iACYYPXjmAv1MJj19fWY9Qv19fX1",
		},
		{
			payload: "KgwSACUQACoMJRAAAAw=",
		},
	}

	for _, tc := range tests {
		p := tc.payload
		b, err := base64.StdEncoding.DecodeString(p)
		if err != nil {
			t.Errorf("Invalid base64 input %q: %v", p, err)
			continue
		}
		cfg := new(api.Configuration)
		if err := proto.Unmarshal(b, cfg); err != nil {
			t.Errorf("Could not unmarshal protobuf: %v", err)
			continue
		}
		log.Println("Configuration: ", cfg.String())
		if _, err := sandwich.NewContext(cfg); tc.wantSuccess != (err == nil) {
			t.Errorf("sandwich.NewContext(%q) = _, %v, want error: %v", cfg.String(), err, !tc.wantSuccess)

		}
	}
}
