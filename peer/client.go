package peer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client is the outbound half of the P2P protocol: what a node uses to
// push shares, fetch shares, and gossip mutation notices to its siblings.
type Client struct {
	HTTP *http.Client
}

func NewClient() *Client {
	return &Client{HTTP: &http.Client{Timeout: 10 * time.Second}}
}

func (c *Client) DeliverShare(endpoint string, req DeliverShareRequest) error {
	return c.postJSON(endpoint+"/peer/deliver", req)
}

// Ping is the cheapest possible liveness check: "is anyone home at this
// endpoint at all," with no authentication and no information beyond
// that — reachability itself already implies WireGuard-mesh membership.
func (c *Client) Ping(endpoint string) error {
	resp, err := c.HTTP.Get(endpoint + "/peer/ping")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("peer: ping %s -> %s", endpoint, resp.Status)
	}
	return nil
}

// CheckPresence asks whether a peer still holds a live share for
// groupID, without ever causing it to decrypt/reveal that share.
func (c *Client) CheckPresence(endpoint, groupID, groupToken string) (PresenceResponse, error) {
	httpReq, err := http.NewRequest(http.MethodGet, endpoint+"/peer/group/"+groupID+"/status", nil)
	if err != nil {
		return PresenceResponse{}, err
	}
	httpReq.Header.Set("X-Group-Token", groupToken)
	resp, err := c.HTTP.Do(httpReq)
	if err != nil {
		return PresenceResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return PresenceResponse{Present: false}, nil
	}
	var out PresenceResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return PresenceResponse{}, err
	}
	return out, nil
}

func (c *Client) NotifyMutation(endpoint string, req MutationNoticeRequest) error {
	return c.postJSON(endpoint+"/peer/mutation-notice", req)
}

// FetchGroupShare asks a peer for its current (already decrypted) share
// of groupID, authenticating with the group's shared token. Addressing by
// group_id rather than a specific pid means reconstruction works even if
// the peer has mutated since the requester last heard about it.
func (c *Client) FetchGroupShare(endpoint, groupID, groupToken string) (ShareResponse, error) {
	httpReq, err := http.NewRequest(http.MethodGet, endpoint+"/peer/group/"+groupID, nil)
	if err != nil {
		return ShareResponse{}, err
	}
	httpReq.Header.Set("X-Group-Token", groupToken)
	resp, err := c.HTTP.Do(httpReq)
	if err != nil {
		return ShareResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return ShareResponse{}, fmt.Errorf("peer: fetch gruppo %s -> %s: %s", groupID, resp.Status, string(b))
	}
	var out ShareResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return ShareResponse{}, err
	}
	return out, nil
}

func (c *Client) postJSON(url string, in any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	resp, err := c.HTTP.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("peer: POST %s -> %s: %s", url, resp.Status, string(b))
	}
	return nil
}
