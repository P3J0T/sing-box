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

func TestTLSECHItem(t *testing.T) {
	t.Parallel()
	item := &TLSECHItem{}
	for _, test := range []struct {
		protocol string
		ech      bool
		match    bool
	}{
		{C.ProtocolTLS, true, true},
		{C.ProtocolTLS, false, false},
		{"", false, false},
		{"", true, false},
		{C.ProtocolQUIC, true, false},
		{C.ProtocolHTTP, true, false},
	} {
		require.Equal(t, test.match, item.Match(&adapter.InboundContext{Protocol: test.protocol, TLSECH: test.ech}))
	}
	require.Equal(t, "tls_ech=true", item.String())
}

func TestTLSECHDefaultRuleOptionalAndCompatible(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name       string
		config     string
		plainMatch bool
	}{
		{"omitted", `{"protocol":"tls","action":"reject"}`, true},
		{"false", `{"protocol":"tls","tls_ech":false,"action":"reject"}`, true},
		{"null", `{"protocol":"tls","tls_ech":null,"action":"reject"}`, true},
		{"true", `{"protocol":"tls","tls_ech":true,"action":"reject"}`, false},
		{"presence_only", `{"tls_ech":true,"action":"reject"}`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var options option.Rule
			require.NoError(t, json.UnmarshalContext(context.Background(), []byte(test.config), &options))
			parsed, err := NewRule(context.Background(), log.NewNOPFactory().Logger(), options, true)
			require.NoError(t, err)
			require.Equal(t, C.RuleActionTypeReject, parsed.Action().Type())
			require.True(t, parsed.Match(&adapter.InboundContext{Protocol: C.ProtocolTLS, TLSECH: true}))
			require.Equal(t, test.plainMatch, parsed.Match(&adapter.InboundContext{Protocol: C.ProtocolTLS}))
			require.False(t, parsed.Match(&adapter.InboundContext{}))
			require.False(t, parsed.Match(&adapter.InboundContext{Protocol: C.ProtocolHTTP}))
		})
	}
}

func TestTLSECHRuleBooleanValidation(t *testing.T) {
	t.Parallel()
	for _, config := range []string{
		`{"tls_ech":"true","action":"reject"}`,
		`{"tls_ech":1,"action":"reject"}`,
		`{"tls_ech":[true],"action":"reject"}`,
	} {
		var options option.Rule
		require.Error(t, json.UnmarshalContext(context.Background(), []byte(config), &options))
	}
}

func TestTLSECHRuleComposition(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		config string
		want   [4]bool // TLS+ECH, ordinary TLS, HTTP, unknown protocol
	}{
		{`{"tls_ech":false,"action":"reject"}`, [4]bool{true, true, true, true}},
		{`{"tls_ech":null,"action":"reject"}`, [4]bool{true, true, true, true}},
		{`{"tls_ech":true,"invert":true,"action":"reject"}`, [4]bool{false, true, true, true}},
		{`{"type":"logical","mode":"and","rules":[{"protocol":"tls"},{"tls_ech":true,"invert":true}],"action":"reject"}`, [4]bool{false, true, false, false}},
		{`{"type":"logical","mode":"or","rules":[{"tls_ech":true},{"protocol":"http"}],"action":"reject"}`, [4]bool{true, false, true, false}},
		{`{"type":"logical","mode":"or","invert":true,"rules":[{"tls_ech":true},{"protocol":"http"}],"action":"reject"}`, [4]bool{false, true, false, true}},
	} {
		var options option.Rule
		require.NoError(t, json.UnmarshalContext(context.Background(), []byte(test.config), &options))
		parsed, err := NewRule(context.Background(), log.NewNOPFactory().Logger(), options, true)
		require.NoError(t, err)
		for index, metadata := range []adapter.InboundContext{
			{Protocol: C.ProtocolTLS, TLSECH: true}, {Protocol: C.ProtocolTLS},
			{Protocol: C.ProtocolHTTP}, {},
		} {
			require.Equal(t, test.want[index], parsed.Match(&metadata), "config=%s, state=%d", test.config, index)
		}
	}
}
