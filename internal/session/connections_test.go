package session

import (
	"context"
	"errors"
	"testing"
)

func TestSumConnections(t *testing.T) {
	// shape mirrors real `dcv list-sessions -j` output
	j := []byte(`[
	  {"id":"alice","num-of-connections":1},
	  {"id":"bob","num-of-connections":2}
	]`)
	n, err := sumConnections(j)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Errorf("got %d, want 3", n)
	}

	if n, _ := sumConnections([]byte(`[]`)); n != 0 {
		t.Errorf("no sessions -> 0, got %d", n)
	}
	if _, err := sumConnections([]byte(`not json`)); err == nil {
		t.Error("expected parse error on bad json")
	}
}

func TestCountConnections(t *testing.T) {
	run := func(_ context.Context, name string, args ...string) ([]byte, error) {
		return []byte(`[{"num-of-connections":2}]`), nil
	}
	n, err := CountConnections(context.Background(), run)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("got %d, want 2", n)
	}

	runErr := func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		return nil, errors.New("dcv down")
	}
	if _, err := CountConnections(context.Background(), runErr); err == nil {
		t.Error("expected error to propagate")
	}
}
