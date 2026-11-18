# SDK-owned GoKrb dependency

Canonical source: [jcmturner/gokrb5](https://github.com/jcmturner/gokrb5), immutable
revision `855dbc707a37a21467aef6c0245fcf3328dc39ed`, `v8/` subtree. This revision
includes the upstream PAC HMAC-SHA256/128 and HMAC-SHA384/192 signature lengths
missing from release v8.4.4.

The source is part of the SDK's root Go module:

```text
github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/...
```

There is no nested module, Git checkout or consumer-local replace directive.
`UPSTREAM.json` records raw source hashes and the archive digest;
`upstream-go.mod.txt` and `upstream-go.sum.txt` retain the original module metadata.
`LICENSE` and `NOTICE` are canonical upstream bytes. See `PATCHES.md` before
refreshing this dependency; a refresh must retain the documented security
contracts and passing cryptographic vectors.

The root SDK requires Go 1.27.4. Ordinary tests include all retained offline
upstream tests and added AES conformance checks. Real external Kerberos, AD and
DNS tests remain explicit opt-ins through `ADSDK_GOKRB5_INTEGRATION`,
`ADSDK_GOKRB5_AD_INTEGRATION` and `ADSDK_GOKRB5_DNS_INTEGRATION` respectively.
These variables require the upstream isolated test infrastructure; setting them
does not qualify the provider's lab matrix.

This library retains canonical compatibility codecs. Their presence does not
authorize the SDK to negotiate legacy encryption, weaken requested SASL
protection, omit channel binding or fall back to another authentication scheme.
SDK authentication policy and actual-session qualification remain separate gates.
