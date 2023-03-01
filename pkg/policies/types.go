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

	"github.com/pkg/errors"
)

// DcfPolicy is a struct for defining behaviors of the DCF
type DcfPolicy struct {
	Name               string             `json:"classifier,omitempty"`      // Name uniquely identifies the policy
	Weights            []Weight           `json:"items,omitempty"`           // Weights contains all of the individual annotation weights
	AttestationOptions AttestationOptions `json:"attestationOpts,omitempty"` // constants pertaining to attestation annotation score calc
}

func (p *DcfPolicy) FetchWeight(key string) Weight {
	w := Weight{}

	for _, item := range p.Weights {
		if item.AnnotationKey == key {
			w = item
			break
		}
	}
	// catch in case the provided key was not found in the defined list of Weights
	if w.Value == 0 {
		w.AnnotationKey = key
		w.Value = 1
	}
	return w
}

// Weight defines the weighting given to an individual annotation result, used when calculating a confidence score
type Weight struct {
	AnnotationKey string `json:"key,omitempty"`   // AnnotationKey indicates the applicable annotation type
	Value         int    `json:"value,omitempty"` // Value indicates the relative importance of the annotation from 1 to 10.
}

func (w *Weight) UnmarshalJSON(data []byte) (err error) {
	type Alias struct {
		AnnotationKey string `json:"key,omitempty"`
		Value         int    `json:"value,omitempty"`
	}
	a := Alias{}
	// Error with unmarshaling
	if err = json.Unmarshal(data, &a); err != nil {
		return err
	}

	if a.Value < 1 {
		a.Value = 1
	} else if a.Value > 10 {
		a.Value = 10
	}
	w.AnnotationKey = a.AnnotationKey
	w.Value = a.Value
	return nil
}

// Defines factors that affect the score calculation of attestation annotations
type AttestationOptions struct {
	CadenceThresholdMins int `json:"cadenceThresholdMins,omitempty"` // The maximum interval in minutes between attestation cycles
	TimeRangeMins        int `json:"timeRange,omitempty"`            // The last N attestation cycles to check during score calculation
}

func (opts *AttestationOptions) UnmarshalJSON(data []byte) (err error) {
	type alias struct {
		CadenceThresholdMins int `json:"cadenceThresholdMins,omitempty"`
		TimeRangeMins        int `json:"timeRange,omitempty"`
	}
	a := alias{}
	if err = json.Unmarshal(data, &a); err != nil {
		return err
	}

	// Validation
	if a.CadenceThresholdMins <= 0 {
		return errors.New("CadenceThresholdMins must be a positive integer")
	}
	if a.TimeRangeMins < 0 {
		return errors.New("CycleRange must be 0 or a positive integer")
	}

	opts.CadenceThresholdMins = a.CadenceThresholdMins
	opts.TimeRangeMins = a.TimeRangeMins
	return nil
}
