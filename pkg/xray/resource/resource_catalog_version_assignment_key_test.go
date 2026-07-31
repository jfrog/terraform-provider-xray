package xray

import "testing"

func TestNewVersionAssignmentKeyKeepsColonPackageNameIntact(t *testing.T) {
	key := newVersionAssignmentKey("mysql:mysql-connector-java", "maven", "8.0.28")

	if key.packageName != "mysql:mysql-connector-java" {
		t.Fatalf("expected package name with colon to be preserved, got %q", key.packageName)
	}
	if key.packageType != "maven" {
		t.Fatalf("expected package type maven, got %q", key.packageType)
	}
	if key.version != "8.0.28" {
		t.Fatalf("expected version 8.0.28, got %q", key.version)
	}
}
