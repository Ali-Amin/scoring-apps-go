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

package documents

import (
	"math"
	"testing"
	"time"

	"github.com/project-alvarium/scoring-apps-go/pkg/policies"
)

func TestAttestScoreCalculation(t *testing.T) {

	attestWeight := 1
	fullRange50MinInterval := policies.AttestationOptions{CadenceThresholdMins: 50, TimeRangeMins: 0}
	last100sAttest20MinInterval := policies.AttestationOptions{CadenceThresholdMins: 20, TimeRangeMins: 100}
	last50sAttest10MinInterval := policies.AttestationOptions{CadenceThresholdMins: 10, TimeRangeMins: 50}
	beforeEpochAnnotation := policies.AttestationOptions{CadenceThresholdMins: 50, TimeRangeMins: 180}
	beforeEpochAnnotation2 := policies.AttestationOptions{CadenceThresholdMins: 50, TimeRangeMins: 50}

	annotations := []Annotation{
		{
			Key:         "1",
			DataRef:     "",
			Hash:        "",
			Host:        "",
			Kind:        "",
			Signature:   "",
			IsSatisfied: true,
			Timestamp:   time.Now().Add(-60 * time.Minute),
		},
		{
			Key:         "2",
			DataRef:     "",
			Hash:        "",
			Host:        "",
			Kind:        "",
			Signature:   "",
			IsSatisfied: true,
			Timestamp:   time.Now().Add(-90 * time.Minute),
		},
		{
			Key:         "3",
			DataRef:     "",
			Hash:        "",
			Host:        "",
			Kind:        "",
			Signature:   "",
			IsSatisfied: true,
			Timestamp:   time.Now().Add(-200 * time.Minute),
		},
	}

	tests := []struct {
		name                 string
		annotations          []Annotation
		opts                 policies.AttestationOptions
		attestWeight         int
		expectedPassedWeight float32
	}{
		// 200 seconds total
		// time attested: 200-150, 90-10: 130
		// 130/200 = 0.65
		{"Since first attestation with 50 min interval", annotations, fullRange50MinInterval, attestWeight, 0.65},

		// 100s total
		// time attested 90-60, 60-40: 40
		// 40/100 = 0.4
		{"Last 100s attestations with 20 min interval", annotations, last100sAttest20MinInterval, attestWeight, 0.4},

		// 50s total
		// no attestations
		{"Last 50s attestations with 10 min interval", annotations, last50sAttest10MinInterval, attestWeight, 0.0},

		// 180s total
		// time atested: 180-150, 90-10: 110
		{"Attestation before time start case 1", annotations, beforeEpochAnnotation, attestWeight, 110.0 / 180.0},

		// 50s total
		// time atested: 50-10
		// 40/50
		{"Attestation before time start case 2", annotations, beforeEpochAnnotation2, attestWeight, 40.0 / 50.0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := calcAttestationScore(tt.annotations, tt.opts, tt.attestWeight)
			t.Log("weight: ", w)
			if math.Round(float64(w)) != math.Round(float64(tt.expectedPassedWeight)) {
				t.Errorf("Incorrect attestation score calculation. Expected: %f got %f", tt.expectedPassedWeight, w)
			}
		})
	}
}
