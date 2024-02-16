// Copyright 2022 The Witness Contributors
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

package policy

import (
	"fmt"
	"strings"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/source"
)

// +kubebuilder:object:generate=true
type Step struct {
	Name          string        `json:"name"`
	Functionaries []Functionary `json:"functionaries"`
	Attestations  []Attestation `json:"attestations"`
	ArtifactsFrom []string      `json:"artifactsFrom,omitempty"`
}

// +kubebuilder:object:generate=true
type Functionary struct {
	Type           string         `json:"type"`
	CertConstraint CertConstraint `json:"certConstraint,omitempty"`
	PublicKeyID    string         `json:"publickeyid,omitempty"`
}

// +kubebuilder:object:generate=true
type Attestation struct {
	Type          string         `json:"type"`
	SubjectScopes []SubjectScope `json:"subjectscopes"`
	RegoPolicies  []RegoPolicy   `json:"regopolicies"`
}

// +kubebuilder:object:generate=true
type RegoPolicy struct {
	Module []byte `json:"module"`
	Name   string `json:"name"`
}

// +kubebuilder:object:generate=true
type SubjectScope struct {
	Subject string `json:"subject"`
	Scope   string `json:"scope"`
}

// StepResult contains information about the verified collections for each step.
// Passed contains the collections that passed any rego policies and all expected attestations exist.
// Rejected contains the rejected collections and the error that caused them to be rejected.
type StepResult struct {
	Step     string
	Passed   []source.VerifiedCollection
	Rejected []RejectedCollection
}

func (r StepResult) HasErrors() bool {
	return len(r.Rejected) > 0
}

func (r StepResult) HasPassed() bool {
	return len(r.Passed) > 0
}

func (r StepResult) Error() string {
	errs := make([]string, len(r.Rejected))
	for i, reject := range r.Rejected {
		errs[i] = reject.Reason.Error()
	}

	return fmt.Sprintf("attestations for step %v could not be used due to:\n%v", r.Step, strings.Join(errs, "\n"))
}

type RejectedCollection struct {
	Collection source.VerifiedCollection
	Reason     error
}

func (f Functionary) Validate(verifier cryptoutil.Verifier, trustBundles map[string]TrustBundle) error {
	verifierID, err := verifier.KeyID()
	if err != nil {
		return fmt.Errorf("could not get key id: %w", err)
	}

	if f.PublicKeyID != "" && f.PublicKeyID == verifierID {
		return nil
	}

	x509Verifier, ok := verifier.(*cryptoutil.X509Verifier)
	if !ok {
		return fmt.Errorf("verifier with ID %v is not a public key verifier or a x509 verifier", verifierID)
	}

	if len(f.CertConstraint.Roots) == 0 {
		return fmt.Errorf("verifier with ID %v is an x509 verifier, but no trusted roots provided in functionary", verifierID)
	}

	if err := f.CertConstraint.Check(x509Verifier, trustBundles); err != nil {
		return fmt.Errorf("verifier with ID %v doesn't meet certificate constraint: %w", verifierID, err)
	}

	return nil
}

// validateAttestations will test each collection against to ensure the expected attestations
// appear in the collection as well as that any rego policies pass for the step.
func (s Step) validateAttestations(verifiedCollections []source.VerifiedCollection) StepResult {
	result := StepResult{Step: s.Name}
	if len(verifiedCollections) <= 0 {
		return result
	}

	for _, collection := range verifiedCollections {
		found := make(map[string]attestation.Attestor)
		for _, attestation := range collection.Collection.Attestations {
			found[attestation.Type] = attestation.Attestation
		}

		passed := true
		for _, expected := range s.Attestations {
			attestor, ok := found[expected.Type]
			if !ok {
				result.Rejected = append(result.Rejected, RejectedCollection{
					Collection: collection,
					Reason: ErrMissingAttestation{
						Step:        s.Name,
						Attestation: expected.Type,
					},
				})

				passed = false
				break
			}

			if err := EvaluateRegoPolicy(attestor, expected.RegoPolicies); err != nil {
				result.Rejected = append(result.Rejected, RejectedCollection{
					Collection: collection,
					Reason:     err,
				})

				passed = false
				break
			}
		}

		if passed {
			result.Passed = append(result.Passed, collection)
		}
	}

	return result
}
