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

package source

import (
	"context"
	"encoding/json"

	"github.com/in-toto/go-witness/archivista"
	"github.com/in-toto/go-witness/dsse"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/updater"
)

type ArchivistaSource struct {
	client      *archivista.Client
	seenGitoids []string
}

func NewArchvistSource(client *archivista.Client) *ArchivistaSource {
	return &ArchivistaSource{
		client:      client,
		seenGitoids: make([]string, 0),
	}
}

func (s *ArchivistaSource) Search(ctx context.Context, collectionName string, subjectDigests, attestations []string) ([]CollectionEnvelope, error) {
	gitoids, err := s.client.SearchGitoids(ctx, archivista.SearchGitoidVariables{
		CollectionName: collectionName,
		SubjectDigests: subjectDigests,
		Attestations:   attestations,
		ExcludeGitoids: s.seenGitoids,
	})

	if err != nil {
		return []CollectionEnvelope{}, err
	}

	envelopes := make([]CollectionEnvelope, 0, len(gitoids))
	for _, gitoid := range gitoids {
		env, err := s.client.Download(ctx, gitoid)
		if err != nil {
			return envelopes, err
		}

		s.seenGitoids = append(s.seenGitoids, gitoid)
		collectionEnv, err := envelopeToCollectionEnvelope(gitoid, env)
		if err != nil {
			return envelopes, err
		}

		envelopes = append(envelopes, collectionEnv)
	}

	return envelopes, nil
}

// return the collection envelope for the policies
func (s *ArchivistaSource) SearchPoliciesBySubjectsName(ctx context.Context, subjects, scopes []string, archivistaURL string, tufUpdater *updater.Updater) ([]dsse.Envelope, error) {
	policies, err := s.client.SearchPolicyBySubjects(
		ctx, archivista.SearchGitoidVariables{Subjects: subjects, Scopes: scopes},
	)

	var policyEnvelopes []dsse.Envelope
	var policyEnvelope dsse.Envelope
	if err != nil {
		return nil, err
	}
	for _, policyName := range policies {
		policyTufInfo, err := tufUpdater.GetTargetInfo("policy/" + policyName)
		if err != nil {
			return nil, err
		}

		// Get the policy gioid from unique policy name
		policyData := &metadata.TargetFiles{}
		_ = json.Unmarshal(*policyTufInfo.Custom, policyData)
		policyGiod := policyData.UnrecognizedFields["gitoid"].(string)

		policyGiodInfo, err := tufUpdater.GetTargetInfo(policyGiod)
		if err != nil {
			return nil, err
		}
		_, p, err := tufUpdater.DownloadTarget(policyGiodInfo, "", archivistaURL+"/download")
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(p, &policyEnvelope)
		if err != nil {
			return nil, err
		}

		policyEnvelopes = append(policyEnvelopes, policyEnvelope)
	}

	return policyEnvelopes, nil
}
