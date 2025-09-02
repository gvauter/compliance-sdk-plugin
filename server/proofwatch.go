// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Resource struct {
	Name      string            `json:"name"`
	URI       string            `json:"uri"`
	Content   json.RawMessage   `json:"content,omitempty"`
	Digest    map[string]string `json:"digest,omitempty"`
	MediaType string            `json:"mediaType,omitempty"`
}

type Metadata struct {
	ID        string    `json:"id"`
	Collected time.Time `json:"collected"`
	Source    string    `json:"source"`
	PolicyID  string    `json:"policyId"`
	Decision  string    `json:"decision"`
	Subject   Resource  `json:"subject"`
}

type Evidence struct {
	Metadata `json:",inline"`
	Details  []Resource `json:"details"`
}

func PushEvidence(ctx context.Context, endpoint string, ev Evidence) error {
	payload, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal evidence: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("post to proofwatch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("proofwatch push failed: %s: %s", resp.Status, string(body))
	}
	return nil
}
