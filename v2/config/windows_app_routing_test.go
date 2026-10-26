package config

import (
	"context"
	"encoding/json"
	"reflect"
	"regexp"
	"strings"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func testWindowsPolicy(t *testing.T, mode string, names, paths []string) *windowsAppRouting {
	t.Helper()
	policy, err := newWindowsAppRouting(&WindowsAppRoutingOptions{Enabled: true, Mode: mode, ProcessNames: names, ProcessPaths: paths}, true, true)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func TestWindowsAppRoutingSelectors(t *testing.T) {
	settings := WindowsAppRoutingOptions{Enabled: true, Mode: "exclude", ProcessNames: []string{"My App+[x].exe"}, ProcessPaths: []string{`C:\Tools (old)\a.b.exe`, `\\server\share\app.exe`}}
	before, _ := json.Marshal(settings)
	policy, err := newWindowsAppRouting(&settings, true, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		path  string
		match bool
	}{
		{`C:\Elsewhere\MY APP+[X].EXE`, true},
		{`c:\TOOLS (OLD)\A.B.EXE`, true},
		{`C:/Tools (old)/a.b.exe`, true},
		{`\\SERVER\SHARE\APP.EXE`, true},
		{`C:\Tools (old)\aXb.exe`, false},
		{`C:\Tools (old)\a.b.exe.extra`, false},
		{`C:\Tools\OtherMy App+[x].exe`, false},
		{`D:\Tools (old)\a.b.exe`, false},
		{"", false},
	} {
		if got := matchesWindowsSelectors(t, policy.selectors, []string{test.path}); got != test.match {
			t.Errorf("path %q: matched %v, want %v", test.path, got, test.match)
		}
	}
	// The runtime supplies every attributed executable/service path; any may match.
	if !matchesWindowsSelectors(t, policy.selectors, []string{`C:\other.exe`, `C:\Tools (old)\a.b.exe`}) {
		t.Fatal("a later attributed path must match")
	}
	after, _ := json.Marshal(settings)
	if string(before) != string(after) {
		t.Fatal("selector compilation mutated stored settings")
	}
}

func TestWindowsAppRoutingValidationAndGating(t *testing.T) {
	for _, test := range []struct {
		name         string
		settings     *WindowsAppRoutingOptions
		windows, tun bool
	}{
		{"absent", nil, true, true},
		{"disabled", &WindowsAppRoutingOptions{Mode: "malformed", ProcessNames: []string{""}}, true, true},
		{"non-Windows", &WindowsAppRoutingOptions{Enabled: true, Mode: "malformed"}, false, true},
		{"non-TUN", &WindowsAppRoutingOptions{Enabled: true, Mode: "malformed"}, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			policy, err := newWindowsAppRouting(test.settings, test.windows, test.tun)
			if err != nil || policy != nil {
				t.Fatalf("inactive policy changed behavior: %v, %v", policy, err)
			}
			stored := DNSOptions{EnableFakeDNS: true}
			if policy.effectiveDNSOptions(stored) != stored || len(policy.routeRules("proxy", "direct")) != 0 || len(policy.dnsRules("remote", "direct", stored)) != 0 {
				t.Fatal("inactive policy must preserve DNS and routes")
			}
		})
	}
	for _, invalid := range []WindowsAppRoutingOptions{
		{Mode: ""}, {Mode: "INCLUDE"}, {Mode: "exclude", ProcessNames: []string{""}},
		{Mode: "include", ProcessNames: []string{`C:\app.exe`}},
		{Mode: "exclude", ProcessNames: []string{"app*.exe"}},
		{Mode: "exclude", ProcessNames: []string{"app\n.exe"}},
		{Mode: "exclude", ProcessPaths: []string{"app.exe"}},
		{Mode: "exclude", ProcessPaths: []string{`C:app.exe`}},
		{Mode: "exclude", ProcessPaths: []string{`C:\Tools\..\app.exe`}},
		{Mode: "exclude", ProcessPaths: []string{`C:\Tools\`}},
		{Mode: "exclude", ProcessPaths: []string{`\\server\app.exe`}},
		{Mode: "exclude", ProcessPaths: []string{`C:\app?.exe`}},
	} {
		invalid.Enabled = true
		if _, err := newWindowsAppRouting(&invalid, true, true); err == nil {
			t.Errorf("accepted malformed active settings: %+v", invalid)
		}
	}
}

func TestWindowsAppRoutingGeneratedJSON(t *testing.T) {
	for _, mode := range []string{"include", "exclude"} {
		t.Run(mode, func(t *testing.T) {
			policy := testWindowsPolicy(t, mode, []string{"selected.exe"}, []string{`C:\Tools\path.exe`})
			stored := DNSOptions{EnableFakeDNS: true, RemoteDnsDomainStrategy: option.DomainStrategy(C.DomainStrategyPreferIPv6), DirectDnsDomainStrategy: option.DomainStrategy(C.DomainStrategyIPv4Only)}
			effective := policy.effectiveDNSOptions(stored)
			if !stored.EnableFakeDNS || stored.IndependentDNSCache || effective.EnableFakeDNS || !effective.IndependentDNSCache {
				t.Fatal("DNS policy mutated stored preferences or failed to isolate answers")
			}
			routes := policy.routeRules("main-proxy", "direct")
			dns := policy.dnsRules("remote-group", "direct-group", effective)
			options := option.Options{Route: &option.RouteOptions{Rules: routes, Final: "main-proxy"}, DNS: &option.DNSOptions{RawDNSOptions: option.RawDNSOptions{DNSClientOptions: option.DNSClientOptions{IndependentCache: effective.IndependentDNSCache}}}}
			for _, rule := range dns {
				options.DNS.Rules = append(options.DNS.Rules, option.DNSRule{Type: C.RuleTypeDefault, DefaultOptions: rule})
			}
			encoded, err := options.MarshalJSONContext(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			var actual map[string]any
			if err := json.Unmarshal(encoded, &actual); err != nil {
				t.Fatal(err)
			}
			for _, collection := range []string{"route", "dns"} {
				object := actual[collection].(map[string]any)
				for _, item := range object["rules"].([]any) {
					rule := item.(map[string]any)
					if rule["inbound"] != "tun-in" {
						t.Errorf("%s rule escaped TUN: %s", collection, encoded)
					}
					for _, forbidden := range []string{"ip_version", "network", "source_ip_cidr", "ip_cidr", "port", "domain"} {
						if _, exists := rule[forbidden]; exists {
							t.Errorf("unexpected %s constraint in %s", forbidden, encoded)
						}
					}
				}
			}
			if !actual["dns"].(map[string]any)["independent_cache"].(bool) {
				t.Fatal("independent cache missing in sing-box JSON")
			}
			if strings.Contains(string(encoded), "fakeip") {
				t.Fatal("FakeIP leaked into active policy")
			}
			selected := "direct"
			if mode == "include" {
				selected = "main-proxy"
			}
			if routes[0].DefaultOptions.RouteOptions.Outbound != selected {
				t.Fatal("selected outbound incorrect")
			}
			if mode == "include" && (len(routes) != 2 || routes[1].DefaultOptions.RouteOptions.Outbound != "direct" || len(routes[1].DefaultOptions.ProcessPathRegex) != 0) {
				t.Fatal("include must end with TUN direct catchall")
			}
			if mode == "exclude" && len(routes) != 1 {
				t.Fatal("exclude must retain standard routes for unselected traffic")
			}
		})
	}
}

func TestWindowsAppRoutingDNSPriority(t *testing.T) {
	for _, mode := range []string{"include", "exclude"} {
		policy := testWindowsPolicy(t, mode, []string{"selected.exe", "svchost.exe", "dnsrslvr.dll"}, nil)
		rules := policy.dnsRules("remote", "direct", DNSOptions{})
		for _, test := range []struct {
			paths []string
			want  string
		}{
			{[]string{`C:\Apps\selected.exe`}, map[string]string{"include": "remote", "exclude": "direct"}[mode]},
			{[]string{`C:\Apps\unselected.exe`}, map[string]string{"include": "direct", "exclude": "remote"}[mode]},
			{[]string{`C:\Windows\System32\SVCHOST.EXE`}, "remote"},
			{[]string{`C:\Apps\selected.exe`, `C:\Windows\System32\dnsrslvr.dll`}, "remote"},
			{nil, "remote"}, {[]string{""}, "remote"}, {[]string{":System"}, "remote"},
			{[]string{":System Idle Process"}, "remote"},
		} {
			got := ""
			for _, rule := range rules {
				if len(rule.ProcessPathRegex) == 0 || matchesWindowsSelectors(t, rule.ProcessPathRegex, test.paths) {
					got = rule.RouteOptions.Server
					break
				}
			}
			if got != test.want {
				t.Errorf("%s DNS for %v: %s, want %s", mode, test.paths, got, test.want)
			}
		}
		for _, rule := range rules {
			if !reflect.DeepEqual([]string(rule.Inbound), []string{"tun-in"}) {
				t.Fatal("DNS policy must be TUN scoped")
			}
		}
	}
}

func TestWindowsAppRoutingEmptySelections(t *testing.T) {
	for _, mode := range []string{"include", "exclude"} {
		policy := testWindowsPolicy(t, mode, nil, nil)
		rules := policy.routeRules("proxy", "direct")
		if mode == "exclude" && len(rules) != 0 {
			t.Fatal("empty exclusion must not select traffic")
		}
		if mode == "include" && (len(rules) != 1 || rules[0].DefaultOptions.RouteOptions.Outbound != "direct") {
			t.Fatal("empty inclusion must direct all TUN traffic")
		}
		dns := policy.dnsRules("remote", "direct", DNSOptions{})
		if dns[len(dns)-1].RouteOptions.Server != "remote" || len(dns[len(dns)-1].ProcessPathRegex) != 0 {
			t.Fatal("unknown DNS fallback must remain remote")
		}
	}
}

func matchesWindowsSelectors(t *testing.T, selectors, paths []string) bool {
	t.Helper()
	for _, selector := range selectors {
		matcher, err := regexp.Compile(selector)
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range paths {
			if matcher.MatchString(path) {
				return true
			}
		}
	}
	return false
}
