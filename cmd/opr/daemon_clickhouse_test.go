package main

import (
	"strings"
	"testing"

	"github.com/oprand/opr/internal/opconfig"
)

func TestClickHouseURLEnvOverridesFile(t *testing.T) {
	fileURL := "http://file.example:8123"
	t.Setenv(opconfig.EnvClickHouseURL, "")
	got, err := clickhouseURL(fileURL)
	if err != nil {
		t.Fatal(err)
	}
	if got != fileURL {
		t.Fatalf("empty OPR_CLICKHOUSE_URL got %q, want the file URL", got)
	}

	t.Setenv(opconfig.EnvClickHouseURL, " http://env.example:8123 ")
	cfg := opconfig.Default()
	cfg.ClickHouse.URL = fileURL
	dm := &Daemon{cfg: cfg, chPassword: "from-env"}
	client, err := dm.clickhouseClient()
	if err != nil {
		t.Fatal(err)
	}
	if client.URL != "http://env.example:8123" {
		t.Fatalf("client URL = %q, want the environment override", client.URL)
	}
	if client.Password != "from-env" {
		t.Fatalf("password = %q, want OPR_CLICKHOUSE_PASSWORD", client.Password)
	}
	if client.Database != cfg.ClickHouse.Database || client.User != cfg.ClickHouse.User {
		t.Fatalf("database/user = %s/%s", client.Database, client.User)
	}
}

func TestClickHouseURLRejectsUserinfo(t *testing.T) {
	t.Setenv(opconfig.EnvClickHouseURL, "")
	_, err := clickhouseURL("http://user:s3cret@127.0.0.1:8123")
	if err == nil {
		t.Fatal("expected userinfo rejection")
	}
	msg := err.Error()
	if strings.Contains(msg, "s3cret") {
		t.Fatalf("error must not echo password: %q", msg)
	}
	if !strings.Contains(msg, opconfig.EnvClickHousePassword) {
		t.Fatalf("error should point at %s: %q", opconfig.EnvClickHousePassword, msg)
	}

	t.Setenv(opconfig.EnvClickHouseURL, "http://user:envsecret@env.example:8123")
	_, err = clickhouseURL("http://127.0.0.1:8123")
	if err == nil {
		t.Fatal("expected env userinfo rejection")
	}
	if strings.Contains(err.Error(), "envsecret") {
		t.Fatalf("error must not echo password: %q", err.Error())
	}
	if !strings.Contains(err.Error(), opconfig.EnvClickHouseURL) {
		t.Fatalf("error should name env var: %q", err.Error())
	}
}
