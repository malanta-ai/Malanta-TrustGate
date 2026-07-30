package reputation

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// MalantaParams bundles the values NewFromParams needs to construct the
// Malanta provider. Kept as plain fields (not config.Config) so this
// package never imports internal/config — config.Config embeds
// *GenericProviderConfig (config depends on reputation), so the reverse
// dependency would be an import cycle.
type MalantaParams struct {
	BaseURL        string
	APIKey         string
	AttemptTimeout time.Duration
	MaxAttempts    int
	MaxConcurrency int
	// BatchSize overrides the number of domains/IPs sent per request (see
	// WithMalantaBatchSize); 0 or an out-of-1-100-range value leaves the
	// built-in default (malantaBatchSize) in place.
	BatchSize int
}

// NewFromParams selects and constructs the configured Provider. provider is
// case-insensitive; empty defaults to "malanta". genericCfg is required
// (and validated via GenericProviderConfig.Validate) only when provider is
// "generic" — the generic provider is never activated implicitly.
// genericMaxConcurrency, when positive, overrides the generic provider's
// own config-block concurrency (see WithGenericConcurrency); 0 is a no-op,
// so callers can pass config.Config.ProviderMaxConcurrency unconditionally.
func NewFromParams(provider string, malanta MalantaParams, genericCfg *GenericProviderConfig, genericAttemptTimeout time.Duration, genericMaxAttempts int, genericMaxConcurrency int) (Provider, error) {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "", "malanta":
		return NewMalanta(malanta.BaseURL, malanta.APIKey,
			WithMalantaRetry(malanta.AttemptTimeout, malanta.MaxAttempts),
			WithMalantaConcurrency(malanta.MaxConcurrency),
			WithMalantaBatchSize(malanta.BatchSize),
		), nil
	case "generic":
		if genericCfg == nil {
			return nil, errors.New("reputation: provider is \"generic\" but no generic provider config was supplied")
		}
		return NewGeneric(*genericCfg,
			WithGenericRetry(genericAttemptTimeout, genericMaxAttempts),
			WithGenericConcurrency(genericMaxConcurrency),
		)
	default:
		return nil, fmt.Errorf("reputation: unknown provider %q", provider)
	}
}
