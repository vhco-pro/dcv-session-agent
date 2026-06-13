package session

import (
	"context"
	"encoding/json"
	"fmt"
)

// CountConnections returns the total number of active DCV client connections
// across ALL virtual sessions on the host. This is the host-wide figure the idle
// accountant needs (spec MU-07): the instance must only stop when every session
// has zero connections, never under one user because another's session looks idle.
func CountConnections(ctx context.Context, run Runner) (int, error) {
	out, err := run(ctx, "dcv", "list-sessions", "-j")
	if err != nil {
		return 0, fmt.Errorf("list-sessions: %w", err)
	}
	total, err := sumConnections(out)
	if err != nil {
		return 0, fmt.Errorf("parsing list-sessions: %w", err)
	}
	return total, nil
}

// sumConnections parses `dcv list-sessions -j` output and sums num-of-connections.
func sumConnections(jsonOut []byte) (int, error) {
	var sessions []struct {
		NumConnections int `json:"num-of-connections"`
	}
	if err := json.Unmarshal(jsonOut, &sessions); err != nil {
		return 0, err
	}
	total := 0
	for _, s := range sessions {
		total += s.NumConnections
	}
	return total, nil
}
