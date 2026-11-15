package rule

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/stretchr/testify/require"
)

func TestTLSECHRuleOptIn(t *testing.T) {
	for _, tc := range []struct {
		name, config   string
		plain, unknown bool
	}{
		{"omitted", `{"protocol":"tls","action":"reject"}`, true, false},
		{"false", `{"protocol":"tls","tls_ech":false,"action":"reject"}`, true, false},
		{"null", `{"protocol":"tls","tls_ech":null,"action":"reject"}`, true, false},
		{"true", `{"protocol":"tls","tls_ech":true,"action":"reject"}`, false, false},
		{"presence", `{"tls_ech":true,"action":"reject"}`, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var opts option.Rule
			require.NoError(t, json.UnmarshalContext(context.Background(), []byte(tc.config), &opts))
			rule, err := NewRule(context.Background(), log.NewNOPFactory().Logger(), opts, true)
			require.NoError(t, err)
			require.True(t, rule.Match(&adapter.InboundContext{Protocol: C.ProtocolTLS, TLSECH: true}))
			require.Equal(t, tc.plain, rule.Match(&adapter.InboundContext{Protocol: C.ProtocolTLS}))
			require.Equal(t, tc.unknown, rule.Match(&adapter.InboundContext{}))
			require.False(t, rule.Match(&adapter.InboundContext{Protocol: C.ProtocolQUIC, TLSECH: true}))
		})
	}
}
