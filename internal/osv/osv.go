package osv

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// OSV API: https://api.osv.dev/v1/query
type Client struct {
	hc      *http.Client
	baseURL string
}

func NewClient(timeout time.Duration) *Client {
	return &Client{
		hc:      &http.Client{Timeout: timeout},
		baseURL: "https://api.osv.dev/v1/query",
	}
}

type QueryRequest struct {
	PURL      string `json:"purl,omitempty"`
	Ecosystem string `json:"ecosystem,omitempty"`
	Name      string `json:"name,omitempty"`
	Version   string `json:"version,omitempty"`
}

type Severity struct {
	Type  string `json:"type,omitempty"`
	Score string `json:"score,omitempty"`
}

type RangeEvent struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

type Range struct {
	Type   string       `json:"type,omitempty"`
	Events []RangeEvent `json:"events,omitempty"`
}

type Affected struct {
	Package struct {
		Ecosystem string `json:"ecosystem,omitempty"`
		Name      string `json:"name,omitempty"`
		PURL      string `json:"purl,omitempty"`
	} `json:"package,omitempty"`
	Ranges   []Range  `json:"ranges,omitempty"`
	Versions []string `json:"versions,omitempty"`
}

type Vuln struct {
	ID       string     `json:"id,omitempty"`
	Summary  string     `json:"summary,omitempty"`
	Details  string     `json:"details,omitempty"`
	Severity []Severity `json:"severity,omitempty"`
	Affected []Affected `json:"affected,omitempty"`
}

type QueryResponse struct {
	Vulns []Vuln `json:"vulns,omitempty"`
}

func (c *Client) Query(req QueryRequest) (*QueryResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequest("POST", c.baseURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.hc.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("osv: http %d", resp.StatusCode)
	}

	var out QueryResponse
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}
