package osv

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

const endpoint = "https://api.osv.dev/v1/query"

type Client struct {
	http *http.Client
}

func NewClient(timeout time.Duration) *Client {
	return &Client{
		http: &http.Client{Timeout: timeout},
	}
}

type QueryRequest struct {
	// Prefer PURL when possible
	PURL string

	// Fallback fields (used when PURL is empty)
	Ecosystem string
	Name      string
	Version   string
}

type QueryResponse struct {
	Vulns []Vuln `json:"vulns"`
}

type Vuln struct {
	ID       string   `json:"id"`
	Summary  string   `json:"summary"`
	Details  string   `json:"details"`
	Aliases  []string `json:"aliases"`
	Modified string   `json:"modified"`
	Published string  `json:"published"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
}

func (c *Client) Query(req QueryRequest) (*QueryResponse, error) {
	if req.PURL == "" && (req.Ecosystem == "" || req.Name == "") {
		return nil, errors.New("osv query: need purl OR (ecosystem+name)")
	}

	payload := map[string]any{}
	if req.PURL != "" {
		payload["package"] = map[string]any{"purl": req.PURL}
	} else {
		payload["package"] = map[string]any{
			"ecosystem": req.Ecosystem,
			"name":      req.Name,
		}
		if req.Version != "" {
			payload["version"] = req.Version
		}
	}

	body, _ := json.Marshal(payload)
	httpReq, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, errors.New("osv query: non-2xx response")
	}

	var out QueryResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}
