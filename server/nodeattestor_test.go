package main_test

import (
	"context"
	"crypto/x509"
	"sync"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	"github.com/spiffe/spire-plugin-sdk/plugintest"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	servernodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire-plugin-sdk/templates/server/nodeattestor"
	"github.com/spiffe/spire/pkg/common/plugin/k8s/apiserver"
	"github.com/stretchr/testify/require"
)

var (
	fooKeyPEM = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIBywIBAAJhAMB4gbT09H2RKXaxbu6IV9C3WY+pvkGAbrlQRIHLHwV3Xt1HchjX
c08v1VEoTBN2YTjhZJlDb/VUsNMJsmBFBBted5geRcbrDtXFlUJ8tQoQx1dWM4Aa
xcdULJ83A9ICKwIDAQABAmBR1asInrIphYQEtHJ/NzdnRd3tqHV9cjch0dAfA5dA
Ar4yBYOsrkaX37WqWSDnkYgN4FWYBWn7WxeotCtA5UQ3SM5hLld67rUqAm2dLrs1
z8va6SwLzrPTu2+rmRgovFECMQDpbfPBRex7FY/xWu1pYv6X9XZ26SrC2Wc6RIpO
38AhKGjTFEMAPJQlud4e2+4I3KkCMQDTFLUvBSXokw2NvcNiM9Kqo5zCnCIkgc+C
hM3EzSh2jh4gZvRzPOhXYvNKgLx8+LMCMQDL4meXlpV45Fp3eu4GsJqi65jvP7VD
v1P0hs0vGyvbSkpUo0vqNv9G/FNQLNR6FRECMFXEMz5wxA91OOuf8HTFg9Lr+fUl
RcY5rJxm48kUZ12Mr3cQ/kCYvftL7HkYR/4rewIxANdritlIPu4VziaEhYZg7dvz
pG3eEhiqPxE++QHpwU78O+F1GznOPBvpZOB3GfyjNQ==
-----END RSA PRIVATE KEY-----`)
	barKeyPEM = []byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgOIAksqKX+ByhLcme
T7MXn5Qz58BJCSvvAyRoz7+7jXGhRANCAATUWB+7Xo/JyFuh1KQ6umUbihP+AGzy
da0ItHUJ/C5HElB5cSuyOAXDQbM5fuxJIefEVpodjqsQP6D0D8CPLJ5H
-----END PRIVATE KEY-----`)
	bazKeyPEM = []byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgpHVYFq6Z/LgGIG/X
+i+PWZEFjGVEUpjrMzlz95tDl4yhRANCAAQAc/I3bBO9XhgTTbLBuNA6XJBSvds9
c4gThKYxugN3V398Eieoo2HTO2L7BBjTp5yh+EUtHQD52bFseBCnZT3d
-----END PRIVATE KEY-----`)
)

type attestorSuite struct {
	serverPlugin         *AttestorPlugin
	serverAttestorClient *servernodeattestorv1.NodeAttestorPluginClient

	//psatData  *common.PSATData
	token     string
	tokenPath string

	t       *testing.T
	require *require.Assertions
}

type AttestorPlugin struct {
	nodeattestorv1.UnimplementedNodeAttestorServer
	configv1.UnimplementedConfigServer

	mu     sync.RWMutex
	config *attestorConfig
	logger hclog.Logger
}

type AttestorConfig struct {
	// Clusters map cluster names to cluster config
	Clusters map[string]*ClusterConfig `hcl:"clusters"`
	// DevIDBundlePath is the DevID trust bundle path
	DevIDBundlePath string `hcl:"devid_ca_path"`
	// EndorsementBundlePath is the Endorsement root CA bundle path
	EndorsementBundlePath string `hcl:"endorsement_ca_path"`
}

// ClusterConfig holds a single cluster configuration
type ClusterConfig struct {
	// Array of allowed service accounts names
	// Attestation is denied if coming from a service account that is not in the list
	ServiceAccountAllowList []string `hcl:"service_account_allow_list"`

	// Audience for PSAT token validation
	// If audience is not configured, defaultAudience will be used
	// If audience value is set to an empty slice, k8s apiserver audience will be used
	Audience *[]string `hcl:"audience"`

	// Kubernetes configuration file path
	// Used to create a k8s client to query the API server. If string is empty, in-cluster configuration is used
	KubeConfigFile string `hcl:"kube_config_file"`

	// Node labels that are allowed to use as selectors
	AllowedNodeLabelKeys []string `hcl:"allowed_node_label_keys"`

	// Pod labels that are allowed to use as selectors
	AllowedPodLabelKeys []string `hcl:"allowed_pod_label_keys"`
}

type clusterConfig struct {
	serviceAccounts      map[string]bool
	audience             []string
	client               apiserver.Client
	allowedNodeLabelKeys map[string]bool
	allowedPodLabelKeys  map[string]bool
}

type attestorConfig struct {
	trustDomain string
	clusters    map[string]*clusterConfig

	devIDRoots *x509.CertPool
	ekRoots    *x509.CertPool
}

func (p *AttestorPlugin) SetLogger(logger hclog.Logger) {
	p.logger = logger
}
func (a *attestorSuite) createAndWriteToken() {
	var err error
	dir := a.t.TempDir()
	dir = dir
	//a.token, err = common.CreatePSAT(a.psatData.Namespace, a.psatData.PodName)
	require.NoError(a.t, err)
	//a.tokenPath = common.WriteToken(a.t, dir, common.TokenRelativePath, a.token)
}

func New() *AttestorPlugin {
	return &AttestorPlugin{}
}

func TestConfigError(t *testing.T) {
	tests := []struct {
		name string
		//		psatData        *common.PSATData
		trustDomain     string
		serverHclConfig string
		expectedErr     string
	}{
		{
			name: "Poorly formatted HCL config",
			//			psatData:        common.DefaultPSATData(),
			serverHclConfig: "poorly formatted hcl",
			expectedErr:     "rpc error: code = InvalidArgument desc = failed to decode configuration",
		},
		{
			name: "Missing trust domain",
			//			psatData:    common.DefaultPSATData(),
			trustDomain: "",
			expectedErr: "rpc error: code = InvalidArgument desc = trust_domain is required",
		},
		{
			name: "Missing cluster",
			//			psatData:    common.DefaultPSATData(),
			trustDomain: "any.domain",
			expectedErr: "rpc error: code = InvalidArgument desc = configuration must have at least one cluster",
		},
		{
			name: "Missing allowed service account",
			//			psatData:    common.DefaultPSATData(),
			trustDomain: "any.domain",
			serverHclConfig: `
				clusters = {
					"any" = {
						service_account_allow_list = []
					}
				}`,
			expectedErr: `rpc error: code = InvalidArgument desc = cluster "any" configuration must have at least one service account allowed`,
		},
		{
			name: "Missing devid certificate path",
			//			psatData:    common.DefaultPSATData(),
			trustDomain: "any.domain",
			serverHclConfig: `
				clusters = {
					"any" = {
						service_account_allow_list = ["SA1"]
					}
				}`,
			expectedErr: `rpc error: code = InvalidArgument desc = devid_ca_path is required`,
		},
		{
			name: "Missing devid endorsement path",
			//			psatData:    common.DefaultPSATData(),
			trustDomain: "any.domain",
			serverHclConfig: `
				clusters = {
					"any" = {
						service_account_allow_list = ["SA1"]
						kube_config_file = ""
						allowed_pod_label_keys = ["PODLABEL-A"]
						allowed_node_label_keys = ["NODELABEL-A"]
					}
				}
				devid_ca_path = "/any/path"`,
			expectedErr: "rpc error: code = InvalidArgument desc = endorsement_ca_path is required",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			a := &attestorSuite{t: t}
			a.require = require.New(t)
			//a.psatData = test.psatData
			a.createAndWriteToken()

			// load and configure server
			s := New()
			serverAttestorClient := new(servernodeattestorv1.NodeAttestorPluginClient)
			serverConfigClient := new(configv1.ConfigServiceClient)
			plugintest.ServeInBackground(t, plugintest.Config{
				PluginServer:   servernodeattestorv1.NodeAttestorPluginServer(s),
				PluginClient:   serverAttestorClient,
				ServiceServers: []pluginsdk.ServiceServer{configv1.ConfigServiceServer(s)},
				ServiceClients: []pluginsdk.ServiceClient{serverConfigClient},
			})
			_, err := serverConfigClient.Configure(context.Background(), &configv1.ConfigureRequest{
				HclConfiguration: test.serverHclConfig,
				CoreConfiguration: &configv1.CoreConfiguration{
					TrustDomain: test.trustDomain,
				},
			})

			a.require.Error(err)
			a.require.Contains(err.Error(), test.expectedErr, "unexpected server configuration error")
		})
	}
}

func Test(t *testing.T) {
	plugin := new(nodeattestor.Plugin)
	naClient := new(nodeattestorv1.NodeAttestorPluginClient)
	configClient := new(configv1.ConfigServiceClient)

	// Serve the plugin in the background with the configured plugin and
	// service servers. The servers will be cleaned up when the test finishes.
	// TODO: Remove the config service server and client if no configuration
	// is required.
	// TODO: Provide host service server implementations if required by the
	// plugin.
	plugintest.ServeInBackground(t, plugintest.Config{
		PluginServer: nodeattestorv1.NodeAttestorPluginServer(plugin),
		PluginClient: naClient,
		ServiceServers: []pluginsdk.ServiceServer{
			configv1.ConfigServiceServer(plugin),
		},
		ServiceClients: []pluginsdk.ServiceClient{
			configClient,
		},
	})

	// TODO: Invoke methods on the clients and assert the results
}
