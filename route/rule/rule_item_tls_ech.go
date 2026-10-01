package rule

import (
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
)

var _ RuleItem = (*TLSECHItem)(nil)

// TLSECHItem matches ECH extension presence in a sniffed TCP TLS ClientHello.
// It also matches ECH GREASE; it does not indicate successful ECH negotiation.
type TLSECHItem struct{}

func (r *TLSECHItem) Match(metadata *adapter.InboundContext) bool {
	return metadata.Protocol == C.ProtocolTLS && metadata.TLSECH
}

func (r *TLSECHItem) String() string {
	return "tls_ech=true"
}
