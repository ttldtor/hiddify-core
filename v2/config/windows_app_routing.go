package config

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

const (
	windowsAppRoutingExclude = "exclude"
	windowsAppRoutingInclude = "include"
	// Absolute paths exclude the :System pseudo-paths returned without an executable owner.
	windowsKnownProcessPath = `(?i)^(?:[a-z]:[\\/]|\\\\[^\\/]+[\\/][^\\/]+[\\/])`
	windowsSharedDNSProcess = `(?i)(?:^|[\\/])(?:svchost\.exe|dnsrslvr\.dll)$`
)

// WindowsAppRoutingOptions selects socket owners, not child processes or delegated work.
type WindowsAppRoutingOptions struct {
	Enabled      bool     `json:"enabled"`
	Mode         string   `json:"mode"`
	ProcessNames []string `json:"process-names"`
	ProcessPaths []string `json:"process-paths"`
}

type windowsAppRouting struct {
	mode      string
	selectors []string
}

func newWindowsAppRouting(settings *WindowsAppRoutingOptions, windows, tun bool) (*windowsAppRouting, error) {
	if settings == nil || !settings.Enabled || !windows || !tun {
		return nil, nil
	}
	if settings.Mode != windowsAppRoutingExclude && settings.Mode != windowsAppRoutingInclude {
		return nil, fmt.Errorf("windows-app-routing: invalid mode %q", settings.Mode)
	}
	policy := &windowsAppRouting{mode: settings.Mode}
	for i, name := range settings.ProcessNames {
		if !validWindowsProcessName(name) {
			return nil, fmt.Errorf("windows-app-routing: invalid process-names[%d]", i)
		}
		policy.selectors = append(policy.selectors, `(?i)(?:^|[\\/])`+regexp.QuoteMeta(name)+`$`)
	}
	for i, path := range settings.ProcessPaths {
		if !validWindowsProcessPath(path) {
			return nil, fmt.Errorf("windows-app-routing: process-paths[%d] must be an absolute executable path", i)
		}
		// Match either Windows separator without interpreting user input as a regex.
		path = strings.ReplaceAll(path, "/", `\`)
		policy.selectors = append(policy.selectors, `(?i)^`+strings.ReplaceAll(regexp.QuoteMeta(path), `\\`, `[\\/]`)+`$`)
	}
	return policy, nil
}

func validWindowsProcessName(name string) bool {
	return name != "" && strings.TrimSpace(name) == name && name != "." && name != ".." &&
		!strings.ContainsAny(name, `\\/:*?"<>|`) && !strings.ContainsFunc(name, unicode.IsControl)
}

func validWindowsProcessPath(path string) bool {
	if path == "" || strings.TrimSpace(path) != path || strings.ContainsFunc(path, unicode.IsControl) {
		return false
	}
	path = strings.ReplaceAll(path, "/", `\`)
	var components []string
	if len(path) >= 3 && ((path[0] >= 'a' && path[0] <= 'z') || (path[0] >= 'A' && path[0] <= 'Z')) && path[1:3] == `:\` {
		components = strings.Split(path[3:], `\`)
	} else if strings.HasPrefix(path, `\\`) {
		components = strings.Split(path[2:], `\`)
		if len(components) < 3 {
			return false
		}
	} else {
		return false
	}
	for _, component := range components {
		if !validWindowsProcessName(component) {
			return false
		}
	}
	return true
}

// effectiveDNSOptions leaves the persisted preference intact. FakeIP cannot safely
// share answers between application routes that use different upstream resolvers.
func (p *windowsAppRouting) effectiveDNSOptions(stored DNSOptions) DNSOptions {
	if p != nil {
		stored.EnableFakeDNS = false
		stored.IndependentDNSCache = true
	}
	return stored
}

func (p *windowsAppRouting) routeRules(proxy, direct string) []option.Rule {
	if p == nil {
		return nil
	}
	var rules []option.Rule
	selectedOutbound := direct
	if p.mode == windowsAppRoutingInclude {
		selectedOutbound = proxy
	}
	if len(p.selectors) > 0 {
		rules = append(rules, windowsProcessRoute(p.selectors, selectedOutbound))
	}
	if p.mode == windowsAppRoutingInclude {
		rules = append(rules, windowsProcessRoute(nil, direct))
	}
	return rules
}

func windowsProcessRoute(selectors []string, outbound string) option.Rule {
	return option.Rule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultRule{
			RawDefaultRule: option.RawDefaultRule{Inbound: []string{InboundTUNTag}, ProcessPathRegex: selectors},
			RuleAction:     option.RuleAction{Action: C.RuleActionTypeRoute, RouteOptions: option.RouteActionOptions{Outbound: outbound}},
		},
	}
}

func (p *windowsAppRouting) dnsRules(remote, direct string, dns DNSOptions) []option.DefaultDNSRule {
	if p == nil {
		return nil
	}
	// Shared resolver traffic has no trustworthy relationship to its requesting app.
	rules := []option.DefaultDNSRule{windowsProcessDNS([]string{windowsSharedDNSProcess}, remote, dns.RemoteDnsDomainStrategy)}
	if len(p.selectors) > 0 {
		server, strategy := direct, dns.DirectDnsDomainStrategy
		if p.mode == windowsAppRoutingInclude {
			server, strategy = remote, dns.RemoteDnsDomainStrategy
		}
		rules = append(rules, windowsProcessDNS(p.selectors, server, strategy))
	}
	if p.mode == windowsAppRoutingInclude {
		rules = append(rules, windowsProcessDNS([]string{windowsKnownProcessPath}, direct, dns.DirectDnsDomainStrategy))
	}
	// Unknown owners and all remaining TUN DNS must stay remote, ahead of domain rules.
	return append(rules, windowsProcessDNS(nil, remote, dns.RemoteDnsDomainStrategy))
}

func windowsProcessDNS(selectors []string, server string, strategy option.DomainStrategy) option.DefaultDNSRule {
	return option.DefaultDNSRule{
		RawDefaultDNSRule: option.RawDefaultDNSRule{Inbound: []string{InboundTUNTag}, ProcessPathRegex: selectors},
		DNSRuleAction: option.DNSRuleAction{
			Action: C.RuleActionTypeRoute,
			RouteOptions: option.DNSRouteActionOptions{
				Server:                        server,
				AbstractDNSRouteActionOptions: option.AbstractDNSRouteActionOptions{Strategy: strategy},
			},
		},
	}
}
