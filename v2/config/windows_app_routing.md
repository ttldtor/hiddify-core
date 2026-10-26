# Windows application routing

`HiddifyOptions.windows-app-routing` applies to the generated configuration on
Windows when `enable-tun` or `enable-tun-service` is enabled. The omitted or
disabled setting, other platforms, and non-TUN configurations retain their
existing behavior. An active policy requires generated configuration; the core
rejects raw-config startup instead of silently skipping the policy.

```json
{
  "windows-app-routing": {
    "enabled": true,
    "mode": "exclude",
    "process-names": ["example.exe"],
    "process-paths": ["C:\\Program Files\\Example\\example.exe"]
  }
}
```

`mode` is `exclude` or `include`. Names and paths form a union. A name matches
the executable basename in any directory; a path matches its full location.
Matching is case-insensitive and treats `/` and `\` as path separators. Values
are exact selectors, escaped before conversion to `process_path_regex`.
Paths must be absolute drive or UNC paths. Empty selectors, relative paths,
wildcards, control characters and `.`/`..` components cause an error while the
policy is active. Inactive settings are ignored. A file need not currently exist;
the selector still applies when it is started at that location.

The route rules apply only to `tun-in`, after sniffing and DNS hijacking and
before built-in special destination rules and the user's routing rules:

| Mode | Selected TUN traffic | Other TUN traffic |
| --- | --- | --- |
| `exclude` | Direct outbound | Existing routing rules and default outbound |
| `include` | Main proxy detour | Direct outbound |

An empty exclusion adds no application route. An empty inclusion directs all
TUN traffic. Application rules contain no network or address-family filter, so
they cover both TCP and UDP, IPv4 and IPv6 where owner lookup succeeds.
Non-TUN inbounds retain their existing routing behavior.

DNS rules use the existing remote and direct DNS groups and precede domain
rules. They apply only to TUN queries:

1. Any attributed path with basename `svchost.exe` or `dnsrslvr.dll` uses remote
   DNS, including when that process was selected by the user.
2. Selected processes use direct DNS in `exclude` mode and remote DNS in
   `include` mode.
3. In `include` mode, an unselected process with an absolute drive or UNC path
   uses direct DNS.
4. Other TUN queries, including queries without owner information and system
   pseudo-paths such as `:System`, use remote DNS.

These rules operate on DNS queries received through TUN. On Windows,
`strict_route` blocks port 53 traffic through other interfaces. A query sent
explicitly to a physical-interface resolver can time out before application
matching; choosing a direct application route does not exempt it from this
platform filter. See [TUN DNS behavior](https://sing-box.sagernet.org/configuration/inbound/tun/#dns_mode).

While active, the effective configuration disables FakeIP and sets the
compatibility `independent_cache` flag. In the pinned sing-box version, cache
entries are separated by DNS transport tag regardless of that deprecated flag.
The stored preferences remain unchanged and take
effect again when application routing is disabled. This also applies to an
empty selection. Direct connections receive real addresses rather than FakeIP
addresses shared with a different DNS policy. The existing direct domain
resolver remains available for direct outbounds and resolver bootstrapping.

Routing depends on socket-owner attribution. Missing or stale attribution can
prevent a selected application rule from matching: `exclude` then follows the
normal routes; `include` then uses its direct catchall. Child processes, shared
services and delegated work are not automatically associated with the selected
executable. A path identifies a location, not a file hash or signature. Existing
connections are not migrated by this setting. Direct uses the system's routes
and does not promise to bypass another VPN.

Implementation references: [policy construction](windows_app_routing.go),
[builder integration](builder.go), [raw-config guard](../hcore/buildconfighelper.go)
and the pinned sing-box [path matcher](../../hiddify-sing-box/route/rule/rule_item_process_path_regex.go).

For contributor verification, audit the imports and package initialization before
running tests. The focused source-only suite creates real sing-box option JSON
from controlled inputs and never starts the core, services, listeners or TUN:

```powershell
Set-Location hiddify-core\v2\config
go test -count=1 -v windows_app_routing.go dns_options.go constant.go windows_app_routing_test.go
```

These tests verify construction and matching expressions. They do not establish
runtime routing or DNS behavior on a Windows network. That requires separate
qualification in an isolated Windows environment.
