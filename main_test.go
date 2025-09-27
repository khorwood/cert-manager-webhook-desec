package main

import (
	"encoding/base64"
	"errors"
	"os"
	"testing"
	"text/template"
	"time"

	acmetest "github.com/cert-manager/cert-manager/test/acme"
)

var (
	token        = os.Getenv("DESEC_TOKEN")
	zone         = os.Getenv("TEST_ZONE_NAME")
	manifestPath = "testdata"
)

func createConfig() error {
	config := []byte(`{
	"apiTokenSecretRef": {
		"name": "desec-token",
		"key": "token"
	}
}
`)
	err := os.WriteFile(manifestPath+"/config.json", config, 0644)
	if err != nil {
		return err
	}

	return nil
}

func createSecret() error {
	if token == "" {
		return errors.New("DESEC_TOKEN should be defined")
	}
	apiTokenBase64 := base64.StdEncoding.EncodeToString([]byte(token))

	secretTmpl := `---
apiVersion: v1
kind: Secret
metadata:
  name: desec-token
type: Opaque
data:
  token: {{.}}
`
	secretFile, err := os.Create(manifestPath + "/secret.yaml")
	if err != nil {
		return err
	}
	defer secretFile.Close()

	tmpl, err := template.New("secret.yaml").Parse(secretTmpl)
	if err != nil {
		return err
	}
	err = tmpl.Execute(secretFile, apiTokenBase64)

	return err
}

func TestRunsSuite(t *testing.T) {
	if len(zone) == 0 {
		t.Fatal("Can't run tests on empty zone, please define TEST_ZONE_NAME")
	}

	if _, err := os.Stat(manifestPath); err != nil {
		err := os.Mkdir(manifestPath, os.FileMode.Perm(0755))
		if err != nil {
			t.Fatal(err)
		}
	}

	if err := createConfig(); err != nil {
		t.Fatal(err)
	}

	if err := createSecret(); err != nil {
		t.Fatal(err)
	}

	pollTime, _ := time.ParseDuration("15s")
	timeOut, _ := time.ParseDuration("5m")

	fixture := acmetest.NewFixture(&desecDNSProviderSolver{},
		acmetest.SetDNSName(zone),
		acmetest.SetDNSServer("ns2.desec.org:53"),
		acmetest.SetResolvedZone(zone),
		acmetest.SetAllowAmbientCredentials(false),
		acmetest.SetManifestPath(manifestPath),
		acmetest.SetPollInterval(pollTime),
		acmetest.SetPropagationLimit(timeOut),
		acmetest.SetStrict(true),
	)

	fixture.RunConformance(t)
}
