package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"

	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
	"github.com/nrdcg/desec"
)

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	cmd.RunWebhookServer(GroupName,
		&desecDNSProviderSolver{},
	)
}

type desecDNSProviderSolver struct {
	client *kubernetes.Clientset
}

type desecDNSProviderConfig struct {
	APITokenSecretRef cmmeta.SecretKeySelector `json:"apiTokenSecretRef"`
}

func (c *desecDNSProviderSolver) Name() string {
	return "desec"
}

func (c *desecDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	desecClient, err := c.getDesecClient(ch)
	if err != nil {
		klog.Error(err)
		klog.Flush()
		return err
	}

	domainName := util.UnFqdn(ch.ResolvedZone)
	subName := util.UnFqdn(strings.TrimSuffix(ch.ResolvedFQDN, ch.ResolvedZone))

	klog.Infof("Calling Get: %s %s %s", domainName, subName, "TXT")
	rrset, err := desecClient.Records.Get(context.Background(), domainName, subName, "TXT")
	if err != nil {
		klog.Info(err)
		klog.Flush()
	}

	if rrset == nil {
		klog.Infof("Calling Create: %s %s %s %s", domainName, subName, "TXT", strconv.Quote(ch.Key))
		_, err := desecClient.Records.Create(context.Background(), desec.RRSet{
			Domain:  domainName,
			SubName: subName,
			Type:    "TXT",
			Records: []string{strconv.Quote(ch.Key)},
			TTL:     60,
		})
		if err != nil {
			klog.Error(err)
			klog.Flush()
			return err
		}
	} else {
		records := rrset.Records
		if !slices.Contains(records, strconv.Quote(ch.Key)) {
			records = append(rrset.Records, strconv.Quote(ch.Key))
		}

		klog.Infof("Calling Update: %s %s %s %s", domainName, subName, "TXT", records)
		_, err := desecClient.Records.Update(context.Background(), domainName, subName, "TXT", desec.RRSet{
			Records: records,
		})
		if err != nil {
			klog.Error(err)
			klog.Flush()
			return err
		}
	}

	return nil
}

func (c *desecDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	desecClient, err := c.getDesecClient(ch)
	if err != nil {
		klog.Error(err)
		return err
	}

	domainName := util.UnFqdn(ch.ResolvedZone)
	subName := util.UnFqdn(strings.TrimSuffix(ch.ResolvedFQDN, ch.ResolvedZone))

	klog.Infof("Calling Get: %s %s %s", domainName, subName, "TXT")
	rrset, err := desecClient.Records.Get(context.Background(), domainName, subName, "TXT")
	if err != nil {
		klog.Error(err)
		return err
	}

	records := slices.DeleteFunc(rrset.Records, func(s string) bool {
		return s == strconv.Quote(ch.Key)
	})

	if len(records) == 0 {
		klog.Infof("Calling Delete: %s %s %s", domainName, subName, "TXT")
		err := desecClient.Records.Delete(context.Background(), domainName, subName, "TXT")
		if err != nil {
			klog.Error(err)
			return err
		}
	} else {
		klog.Infof("Calling Update: %s %s %s %s", domainName, subName, "TXT", records)
		_, err := desecClient.Records.Update(context.Background(), domainName, subName, "TXT", desec.RRSet{
			Records: records,
		})
		if err != nil {
			klog.Error(err)
			return err
		}
	}

	return nil
}

func (c *desecDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		klog.Error(err)
		return err
	}

	c.client = cl

	return nil
}

func (c *desecDNSProviderSolver) getDesecClient(ch *v1alpha1.ChallengeRequest) (*desec.Client, error) {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return nil, err
	}

	sec, err := c.client.CoreV1().Secrets(ch.ResourceNamespace).Get(context.Background(), cfg.APITokenSecretRef.Name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("unable to get secret `%s/%s`; %v", cfg.APITokenSecretRef.Name, ch.ResourceNamespace, err)
	}

	data, ok := sec.Data[cfg.APITokenSecretRef.Key]
	if !ok {
		return nil, fmt.Errorf("key `%q` not found in secret `%s/%s`", cfg.APITokenSecretRef.Key, ch.ResourceNamespace, sec.Name)
	}

	client := desec.New(string(data), desec.NewDefaultClientOptions())

	return client, nil
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func loadConfig(cfgJSON *extapi.JSON) (desecDNSProviderConfig, error) {
	cfg := desecDNSProviderConfig{}
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}
