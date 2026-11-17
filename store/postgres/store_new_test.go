package postgres

import (
	"strings"
	"testing"

	"go.uber.org/zap"
)

func TestNewRejectsBadDSNWithoutLeaking(t *testing.T) {
	t.Parallel()
	// Malformed host: pgx's own error can still quote userinfo; New must not.
	secret := "postgresql://user:supersecret@[::1"
	_, err := New(zap.NewNop(), secret)
	if err == nil {
		t.Fatal("expected parse error for malformed DSN")
	}
	msg := err.Error()
	if strings.Contains(msg, "supersecret") || strings.Contains(msg, secret) || strings.Contains(msg, "user:supersecret") {
		t.Fatalf("error must not include DSN or password: %q", msg)
	}
	if msg != "unable to parse postgres DSN" {
		t.Fatalf("got %q, want unable to parse postgres DSN", msg)
	}
}

func TestNewRejectsInvalidPoolSettingWithoutLeaking(t *testing.T) {
	t.Parallel()
	dsn := "postgres://user:anothersecret@127.0.0.1:5432/opr?pool_max_conns=abc"
	_, err := New(zap.NewNop(), dsn)
	if err == nil {
		t.Fatal("expected parse error for invalid pool_max_conns")
	}
	msg := err.Error()
	if strings.Contains(msg, "anothersecret") || strings.Contains(msg, dsn) {
		t.Fatalf("error must not include DSN or password: %q", msg)
	}
	if msg != "unable to parse postgres DSN" {
		t.Fatalf("got %q, want unable to parse postgres DSN", msg)
	}
}
