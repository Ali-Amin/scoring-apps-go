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
	"sort"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/project-alvarium/alvarium-sdk-go/pkg/contracts"
	"github.com/project-alvarium/scoring-apps-go/pkg/policies"
)

const (
	EdgeLineage       string = "lineage"
	EdgeScoring       string = "scoring"
	EdgeTrust         string = "trust"
	VertexAnnotations string = "annotations"
	VertexData        string = "data"
	VertexScores      string = "scores"
)

// Data represents a document in the "data" vertex collection
type Data struct {
	Key       string    `json:"_key,omitempty"`      // Key uniquely identifies the document in the database
	Timestamp time.Time `json:"timestamp,omitempty"` // Timestamp indicates when the document was created
}

// Annotation represents a document in the "annotation" vertex collection
type Annotation struct {
	Key         string             `json:"_key,omitempty"`      // Key uniquely identifies the document in the database
	DataRef     string             `json:"dataRef,omitempty"`   // DataRef points to the key of the data being annotated
	Hash        contracts.HashType `json:"hash,omitempty"`      // Hash identifies which algorithm was used to construct the hash
	Host        string             `json:"host,omitempty"`      // Host is the hostname of the node making the annotation
	Kind        string             `json:"type,omitempty"`      // Kind indicates what kind of annotation this is. Defined as string to allow for annotation types outside of the Alvarium Go SDK
	Signature   string             `json:"signature,omitempty"` // Signature contains the signature of the party making the annotation
	IsSatisfied bool               `json:"isSatisfied"`         // IsSatisfied indicates whether the criteria defining the annotation were fulfilled
	Timestamp   time.Time          `json:"timestamp,omitempty"` // Timestamp indicates when the annotation was created
}

// NewAnnotation will map an Alvarium SDK annotation into an Annotation document
func NewAnnotation(a contracts.Annotation) Annotation {
	return Annotation{
		Key:         a.Id.String(),
		DataRef:     a.Key,
		Hash:        a.Hash,
		Host:        a.Host,
		Kind:        string(a.Kind),
		Signature:   a.Signature,
		IsSatisfied: a.IsSatisfied,
		Timestamp:   a.Timestamp,
	}
}

// Score represents a document in the "score" vertex collection
type Score struct {
	Key        ulid.ULID `json:"_key,omitempty"`       // Key uniquely identifies the document in the database
	DataRef    string    `json:"dataRef,omitempty"`    // DataRef points to the key of the data being annotated
	Passed     int       `json:"score,omitempty"`      // Passed indicates how many of the annotations for a given dataRef were Satisfied
	Count      int       `json:"count,omitempty"`      // Count indicates the total number of annotations applicable to a dataRef
	Policy     string    `json:"policy,omitempty"`     // Policy will indicate some version of the policy used to calculate confidence
	Confidence float64   `json:"confidence,omitempty"` // Confidence is the percentage of trust in the dataRef
	Timestamp  time.Time `json:"timestamp,omitempty"`  // Timestamp indicates when the score was calculated
}

func NewScore(dataRef string, annotations []Annotation, policy policies.DcfPolicy) Score {
	var totalWeight, passedWeight float32
	var passed int

	// Annotations with unique score calculation separated from other "generic" annotations
	var attestAnnotations []Annotation
	var genericAnnotations []Annotation
	for _, a := range annotations {
		if a.Kind == string(contracts.AnnotationAttestation) {
			attestAnnotations = append(attestAnnotations, a)
		} else {
			genericAnnotations = append(genericAnnotations, a)
		}
	}

	for _, a := range genericAnnotations {
		w := policy.FetchWeight(a.Kind)
		totalWeight += float32(w.Value)
		if a.IsSatisfied {
			passed++
			passedWeight += float32(w.Value)
		}
	}
	// Attestation score calculation separate from others then added to total
	attestationWeight := policy.FetchWeight(string(contracts.AnnotationAttestation))
	passedAttest := calcAttestationScore(attestAnnotations, policy.AttestationOptions, attestationWeight.Value)
	passedWeight += passedAttest
	totalWeight += float32(attestationWeight.Value)

	confidence := float64(passedWeight / totalWeight)
	confidence = math.Round(confidence*100) / 100

	s := Score{
		Key:        NewULID(),
		DataRef:    dataRef,
		Passed:     passed,
		Count:      len(annotations),
		Policy:     policy.Name,
		Confidence: confidence,
		Timestamp:  time.Now(),
	}
	return s
}

// Attestation score calculated as the ratio of successful attestation cycles
// to the total expected total number of attestation cycles up until "now"
//
// The ratio is normalized on the attestation annotation weight set by policy and
// added to the rest of the annotations' weight
//
// An optional CycleRange parameter set by policy can be used to limit how far
// back the calculation goes when checking attestations if interest in
// attestation periodicity is short-term only. This can be useful when e.g. the
// device has been down for a prolonged period of time a long time ago and
// it is desired that this does not effect current confidence score
func calcAttestationScore(attestAnnotations []Annotation, opts policies.AttestationOptions, weight int) (passedWeight float32) {
	var earliestAttestLimit time.Time
	var filteredAnnotations []Annotation
	if opts.TimeRangeMins == 0 { // if value not set, use device lifetime
		filteredAnnotations = attestAnnotations
	} else {
		earliestAttestLimit = time.Now().Add(-time.Minute * (time.Duration(opts.TimeRangeMins)))
		for _, a := range attestAnnotations {
			if a.Timestamp.After(earliestAttestLimit.Add(-time.Minute * time.Duration(opts.CadenceThresholdMins))) {
				filteredAnnotations = append(filteredAnnotations, a)
			}
		}
	}

	if len(filteredAnnotations) == 0 { // no attestations found
		return 0
	}

	sort.Slice(filteredAnnotations, func(i, j int) bool {
		return attestAnnotations[i].Timestamp.Before(attestAnnotations[j].Timestamp)
	})

	if opts.TimeRangeMins == 0 { // get earliest time if no window specified
		earliestAttestLimit = filteredAnnotations[0].Timestamp
	}

	var trustedAttestationPeriod float32
	var prevAttest Annotation
	for _, a := range filteredAnnotations {
		if a.Timestamp.Before(earliestAttestLimit) {
			trustedAttestationPeriod = float32(opts.CadenceThresholdMins) - float32(earliestAttestLimit.Sub(a.Timestamp).Minutes())
			continue
		} else if (prevAttest == Annotation{}) {
			prevAttest = a
			continue
		}

		trustedAttestationPeriod += float32(
			math.Min(a.Timestamp.Sub(prevAttest.Timestamp).Minutes(), float64(opts.CadenceThresholdMins)),
		)
		prevAttest = a
	}

	if (prevAttest != Annotation{}) {
		trustedAttestationPeriod += float32(
			math.Min(time.Since(prevAttest.Timestamp).Minutes(), float64(opts.CadenceThresholdMins)),
		)
	}

	passedWeight = trustedAttestationPeriod / float32(time.Since(earliestAttestLimit).Minutes()) * float32(weight)
	return passedWeight
}

// Trust represents a document in the "trust" edge collection
type Trust struct {
	From string `json:"_from"`
	To   string `json:"_to"`
}

// Lineage represents a document in the "lineage" edge collection
type Lineage struct {
	From string `json:"_from"`
	To   string `json:"_to"`
}

// Scoring represents a document in the "scoring" edge collection
type Scoring struct {
	From string `json:"_from"`
	To   string `json:"_to"`
}
