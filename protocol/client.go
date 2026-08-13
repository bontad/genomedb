package protocol

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// OrchestratorClient is the thin HTTP client a client-daemon uses to speak
// the protocol to the Server-Orchestrator.
type OrchestratorClient struct {
	BaseURL string
	HTTP    *http.Client
}

func NewOrchestratorClient(baseURL string) *OrchestratorClient {
	return &OrchestratorClient{BaseURL: baseURL, HTTP: &http.Client{Timeout: 10 * time.Second}}
}

func (c *OrchestratorClient) postJSON(path string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	resp, err := c.HTTP.Post(c.BaseURL+path, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("protocol: %s -> %s: %s", path, resp.Status, string(b))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *OrchestratorClient) Register(req RegisterRequest) error {
	var resp RegisterResponse
	return c.postJSON("/register", req, &resp)
}

func (c *OrchestratorClient) AnnounceRoute(a RouteAnnounce) error {
	return c.postJSON("/route/announce", a, nil)
}

func (c *OrchestratorClient) Heartbeat(hb Heartbeat) error {
	return c.postJSON("/heartbeat", hb, nil)
}

func (c *OrchestratorClient) Ack(ack MutationAck) error {
	return c.postJSON("/mutation/ack", ack, nil)
}

func (c *OrchestratorClient) Alert(alert ImmuneAlert) error {
	return c.postJSON("/alert", alert, nil)
}

// ListNodes fetches the public node directory (node_id -> endpoint), used
// for peer discovery when splitting a new secret.
func (c *OrchestratorClient) ListNodes() ([]NodeInfo, error) {
	resp, err := c.HTTP.Get(c.BaseURL + "/nodes")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var nodes []NodeInfo
	if err := json.NewDecoder(resp.Body).Decode(&nodes); err != nil {
		return nil, err
	}
	return nodes, nil
}

// GetMap fetches a full routing-table snapshot. Used for initial peer
// discovery (finding the endpoint currently serving a pseudo-ID) — the
// incremental path for staying in sync is the /events delta stream.
func (c *OrchestratorClient) GetMap() ([]RouteEntry, error) {
	resp, err := c.HTTP.Get(c.BaseURL + "/map")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var entries []RouteEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, err
	}
	return entries, nil
}

// Event is one Server-Sent Event delivered on the control channel.
type Event struct {
	Type string // "mutation_seed" | "map_delta"
	Data json.RawMessage
}

// SubscribeEvents opens the persistent control channel and streams
// server-pushed MUTATION_SEED and MAP_DELTA events until ctx is
// cancelled or the connection drops (caller is expected to retry).
func (c *OrchestratorClient) SubscribeEvents(ctx context.Context, nodeID string) (<-chan Event, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/events?node_id="+nodeID, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		resp.Body.Close()
		return nil, fmt.Errorf("protocol: /events -> %s", resp.Status)
	}

	ch := make(chan Event, 16)
	go func() {
		defer close(ch)
		defer resp.Body.Close()
		scanner := bufio.NewScanner(resp.Body)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		var evType string
		for scanner.Scan() {
			line := scanner.Text()
			switch {
			case strings.HasPrefix(line, "event: "):
				evType = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "data: "):
				data := strings.TrimPrefix(line, "data: ")
				select {
				case ch <- Event{Type: evType, Data: json.RawMessage(data)}:
				case <-ctx.Done():
					return
				}
			case line == "":
				// event boundary, nothing to do
			}
		}
	}()
	return ch, nil
}
