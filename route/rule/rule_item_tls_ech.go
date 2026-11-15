package rule

import (
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
)

var _ RuleItem = (*TLSECHItem)(nil)

// TLSECHItem matches the outer TCP TLS extension, including ECH GREASE.
// It does not establish successful ECH negotiation or reveal an inner name.
type TLSECHItem struct{}

func (*TLSECHItem) Match(metadata *adapter.InboundContext) bool {
	return metadata.Protocol == C.ProtocolTLS && metadata.TLSECH
}

func (*TLSECHItem) String() string { return "tls_ech=true" }
