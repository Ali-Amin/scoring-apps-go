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

package policy

import (
	"fmt"

	"github.com/project-alvarium/scoring-apps-go/internal/config"
	"github.com/project-alvarium/scoring-apps-go/pkg/policies"
)

type LocalPolicyProvider struct {
	policy []policies.DcfPolicy
}

func (lp *LocalPolicyProvider) GetWeights(classifier string) ([]policies.Weight, error) {
	for _, p := range lp.policy {
		if p.Name == classifier {
			return p.Weights, nil
		}
	}
	return nil, fmt.Errorf("classifier not defined %s", classifier)
}

func (lp *LocalPolicyProvider) GetAttestationOpts(classifier string) (policies.AttestationOptions, error) {
	for _, p := range lp.policy {
		if p.Name == classifier {
			return p.AttestationOptions, nil
		}
	}
	return policies.AttestationOptions{}, fmt.Errorf("classifier not defined %s", classifier)
}

func NewLocalPolicyProvider(cfg config.LocalPolicyConfig) PolicyProvider {

	localPolicyProvider := LocalPolicyProvider{}
	localPolicyProvider.policy = cfg.Dcf

	return &localPolicyProvider
}
