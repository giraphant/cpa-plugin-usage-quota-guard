package abi

import (
	"encoding/json"
	"testing"
)

func TestOKEnvelope(t *testing.T) {
	raw, err := OKEnvelope(map[string]string{"hello": "world"})
	if err != nil {
		t.Fatalf("OKEnvelope returned error: %v", err)
	}
	var got Envelope
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	if !got.OK {
		t.Fatalf("OK = false, want true")
	}
	var result map[string]string
	if err := json.Unmarshal(got.Result, &result); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if result["hello"] != "world" {
		t.Fatalf("result[hello] = %q", result["hello"])
	}
}

func TestErrorEnvelope(t *testing.T) {
	raw := ErrorEnvelope("bad", "something failed")
	var got Envelope
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	if got.OK {
		t.Fatalf("OK = true, want false")
	}
	if got.Error == nil || got.Error.Code != "bad" || got.Error.Message != "something failed" {
		t.Fatalf("unexpected error: %+v", got.Error)
	}
}
