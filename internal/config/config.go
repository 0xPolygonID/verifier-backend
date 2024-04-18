package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/kelseyhightower/envconfig"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

// CallbackURL is the callback endpoint
const CallbackURL string = "/callback"

// CacheTTL is the cache expiration time
type CacheTTL time.Duration

// Config holds the project configuration
type Config struct {
	Host                 string   `envconfig:"host" default:"http://localhost"`
	ApiPort              string   `envconfig:"port" default:"3009"`
	KeyDIR               string   `envconfig:"keydir" default:"./keys"`
	IPFSURL              string   `envconfig:"ipfs_url" default:"https://gateway.pinata.cloud"`
	ResolverSettingsPath string   `envconfig:"resolver_settings_path" default:"./resolvers_settings.yaml"`
	CacheExpiration      CacheTTL `envconfig:"cache_expiration" default:"48h"`
	ResolverSettings     ResolverSettings
}

// ResolverSettings holds the resolver settings
type ResolverSettings map[string]map[string]ResolverSettingsAttrs

// ResolverSettingsAttrs holds the resolver settings attributes
type ResolverSettingsAttrs struct {
	ContractAddress string `yaml:"contractAddress"`
	NetworkURL      string `yaml:"networkURL"`
	ChainID         string `yaml:"chainID"`
	NetworkFlag     byte   `yaml:"networkFlag"`
	DID             string `yaml:"did"`
}

// Load loads the configuration from the environment
func Load() (*Config, error) {
	conf := &Config{}
	if err := envconfig.Process("VERIFIER_BACKEND", conf); err != nil {
		return nil, err
	}
	rs, err := parseResolversSettings(conf.ResolverSettingsPath)
	if err != nil {
		log.Error("failed to parse resolvers settings")
		return nil, err
	}
	conf.ResolverSettings = rs
	return conf, nil
}

func parseResolversSettings(resolverSettingsPath string) (ResolverSettings, error) {
	f, err := os.Open(filepath.Clean(resolverSettingsPath))
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Println("failed to close setting file:", err)
		}
	}()

	settings := ResolverSettings{}
	if err := yaml.NewDecoder(f).Decode(&settings); err != nil {
		return nil, fmt.Errorf("invalid yaml file: %v", settings)
	}
	return settings, nil
}

// Decode parses the duration string. It implements the envconfig.Decoder interface.
func (cttl *CacheTTL) Decode(value string) error {
	d, err := time.ParseDuration(value)
	if err != nil {
		log.WithFields(log.Fields{
			"value": value,
		}).Error("failed to parse cache expiration")
		return err
	}
	log.Info("cache expiration set to ", d)
	*cttl = CacheTTL(d)
	return nil
}

// AsDuration returns the cache expiration as a time.Duration
func (cttl *CacheTTL) AsDuration() time.Duration {
	return time.Duration(*cttl)
}
