package api

import (
	"encoding/json"
	"testing"

	"github.com/iden3/go-iden3-auth/v2/loaders"
	"github.com/stretchr/testify/require"

	"github.com/0xPolygonID/verifier-backend/internal/config"
)

var (
	cfg        config.Config
	keysLoader *loaders.FSKeyLoader
)

func TestMain(m *testing.M) {
	cfg = config.Config{
		Host:    "http://localhost",
		ApiPort: "3000",
		KeyDIR:  "./keys",
		IPFSURL: "https://gateway.pinata.cloud",
		ResolverSettings: config.ResolverSettings{
			"polygon": {
				"mumbai": {
					ContractAddress: "0x2C1DdDc4C8b6BdAaE831eF04bF4FfDfA575d8bA7",
					NetworkURL:      "https://rpc-mumbai.maticvigil.com",
				},
			},
		},
	}

	keysLoader = &loaders.FSKeyLoader{Dir: cfg.KeyDIR}
	m.Run()
}

func jsonToMap(t *testing.T, jsonStr string) map[string]interface{} {
	result := make(map[string]interface{})
	require.NoError(t, json.Unmarshal([]byte(jsonStr), &result))
	return result
}
