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

package archivista

import (
	"context"

	archivistaapi "github.com/in-toto/archivista/pkg/api"
)

type searchGitoidResponse struct {
	Dsses struct {
		Edges []struct {
			Node struct {
				Gitoid string `json:"gitoidSha256"`
			} `json:"node"`
		} `json:"edges"`
	} `json:"dsses"`
}

type SearchGioidsBySubjectResponse struct {
	Dsses struct {
		Edges []struct {
			Node struct {
				Gitoid    string `json:"gitoidSha256"`
				Statement struct {
					Policies struct {
						Edges []struct {
							Node struct {
								Name string `json:"name"`
							} `json:"node"`
						} `json:"edges"`
					} `json:"policies"`
				} `json:"statement"`
			} `json:"node"`
		} `json:"edges"`
	} `json:"dsses"`
}

type SearchGitoidVariables struct {
	SubjectDigests []string `json:"subjectDigests"`
	CollectionName string   `json:"collectionName"`
	Attestations   []string `json:"attestations"`
	ExcludeGitoids []string `json:"excludeGitoids"`
	Subjects       []string `json:"subjects"`
	Scopes         []string `json:"scopes"`
}

func (c *Client) SearchGitoids(ctx context.Context, vars SearchGitoidVariables) ([]string, error) {
	const queryDigestsOnly = `query ($subjectDigests: [String!]) {
		dsses(
		  where: {
				  hasStatementWith: {
					  hasSubjectsWith: {
						  hasSubjectDigestsWith: {
							  valueIn: $subjectDigests
						  }
					  }
				  }
			  }
		) {
		  edges {
			node {
			  gitoidSha256
			}
		  }
		}
	  }`

	const queryFull = `query ($subjectDigests: [String!], $attestations: [String!], $collectionName: String!, $excludeGitoids: [String!]) {
		dsses(
			where: {
					gitoidSha256NotIn: $excludeGitoids,
					hasStatementWith: {
						hasAttestationCollectionsWith: {
							name: $collectionName,
							hasAttestationsWith: {
								typeIn: $attestations
							}
						},
						hasSubjectsWith: {
							hasSubjectDigestsWith: {
								valueIn: $subjectDigests
							}
						}
					}
				}
		) {
			edges {
			node {
				gitoidSha256
			}
		  }
		}
	}`
	var query string
	if len(vars.Attestations) == 0 && len(vars.CollectionName) == 0 && len(vars.ExcludeGitoids) == 0 {
		query = queryDigestsOnly
	} else {
		query = queryFull
	}

	response, err := archivistaapi.GraphQlQuery[searchGitoidResponse](ctx, c.url, query, vars)
	if err != nil {
		return nil, err
	}

	gitoids := make([]string, 0, len(response.Dsses.Edges))
	for _, edge := range response.Dsses.Edges {
		gitoids = append(gitoids, edge.Node.Gitoid)
	}

	return gitoids, nil
}

func (c *Client) SearchPolicyBySubjects(ctx context.Context, vars SearchGitoidVariables) ([]string, error) {
	const query = `query ($subjects: [String!], $scopes: [String!]) {
		dsses(
		  where: {
			payloadTypeHasPrefix: "https://witness.testifysec.com/policy/v0.1",
			and: {
			  hasStatementWith: {
				hasPoliciesWith: {
				  hasSubjectScopesWith: {
					and: [
					  { subjectIn: $subjects }
					  { scopeIn: $scopes }
					]
				  }
				}
			  }
			}
		  }
		) {
		  edges {
			node {
			  gitoidSha256
			  statement {
				policies {
				  edges {
					node {
					  name
					}
				  }
				}
			  }
			}
		  }
		}
	  }`

	var policies []string
	response, err := archivistaapi.GraphQlQuery[SearchGioidsBySubjectResponse](ctx, c.url, query, vars)
	if err != nil {
		return nil, err
	}

	for _, edge := range response.Dsses.Edges {
		for _, policy := range edge.Node.Statement.Policies.Edges {
			policies = append(policies, policy.Node.Name)
		}
	}

	return policies, nil
}
