/*******************************************************************************
 * Copyright 2022 Dell Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 *******************************************************************************/

package policies

import (
	"encoding/json"
	"testing"
)

func TestWeightUnmarshal(t *testing.T) {
	weightOK := Weight{
		AnnotationKey: "tpm",
		Value:         5,
	}

	weightMin := Weight{
		AnnotationKey: "min",
	}

	weightMax := Weight{
		AnnotationKey: "max",
		Value:         100,
	}

	tests := []struct {
		name string
		w    Weight
	}{
		{"weight normal", weightOK},
		{"weight value empty", weightMin},
		{"weight value too high", weightMax},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, _ := json.Marshal(tt.w)
			var x Weight
			json.Unmarshal(b, &x)
			switch tt.w.AnnotationKey {
			case "tpm":
				if x.AnnotationKey != tt.w.AnnotationKey || x.Value != tt.w.Value {
					t.Error("failed to unmarshal correctly")
				}
			case "min":
				if x.Value != 1 {
					t.Errorf("expected Value of 1, received %v", x.Value)
				}
			case "max":
				if x.Value != 10 {
					t.Errorf("expected Value of 10, received %v", x.Value)
				}
			}
		})
	}
}

func TestAttestationOptsUnmarshal(t *testing.T) {
	ok := AttestationOptions{
		CadenceThresholdMins: 50,
		TimeRangeMins:        2,
	}

	okTimeRangeMinsZero := AttestationOptions{
		CadenceThresholdMins: 50,
		TimeRangeMins:        0,
	}

	badCadenceNegative := AttestationOptions{
		CadenceThresholdMins: -1,
		TimeRangeMins:        2,
	}

	badCadenceZero := AttestationOptions{
		CadenceThresholdMins: 0,
		TimeRangeMins:        2,
	}

	badTimeRangeMinsNegative := AttestationOptions{
		CadenceThresholdMins: 50,
		TimeRangeMins:        -1,
	}

	tests := []struct {
		name        string
		opts        AttestationOptions
		expectError bool
	}{
		{"Positive attestation cadence and range", ok, false},
		{"Positive attestation cadence and zero range", okTimeRangeMinsZero, false},
		{"Negative attestation cadence", badCadenceNegative, true},
		{"Zero attestation cadence", badCadenceZero, true},
		{"Negative cycle range", badTimeRangeMinsNegative, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, _ := json.Marshal(tt.opts)
			var opts AttestationOptions
			err := json.Unmarshal(b, &opts)
			if err == nil && tt.expectError {
				t.Errorf("Test did not throw error when expected to: %s", tt.name)
			}
			if err != nil && !tt.expectError {
				t.Errorf("Test did threw error when not expected to.\n test: %b\nerror:%s", opts, err)
			}

		})
	}
}
