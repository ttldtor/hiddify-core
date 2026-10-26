package config

import "github.com/sagernet/sing-box/option"

type DNSOptions struct {
	RemoteDnsAddress        string                `json:"remote-dns-address,omitempty" overridable:"true"`
	RemoteDnsDomainStrategy option.DomainStrategy `json:"remote-dns-domain-strategy,omitempty" overridable:"true"`
	DirectDnsAddress        string                `json:"direct-dns-address,omitempty" overridable:"true"`
	DirectDnsDomainStrategy option.DomainStrategy `json:"direct-dns-domain-strategy,omitempty" overridable:"true"`
	IndependentDNSCache     bool                  `json:"independent-dns-cache,omitempty"`
	EnableFakeDNS           bool                  `json:"enable-fake-dns,omitempty"`
}
