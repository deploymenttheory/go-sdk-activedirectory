# SDK11 offline audit evidence

These records are an audit and publication check, **not new live AD evidence**.
The [qualification ledger](../../provider-qualification.md) retains all remaining
release gates. Original TLS, Kerberos, SASL and descriptor captures stay in their
existing directories without modification.

`authentication-audit.json` was produced by the byte-preserved
`executed-auth-audit.py.txt` against raw Git commit
`14a927a609b0a47d39cd0dc14023ebec4b8a8ca2`. It separately audits Server2016
candidate evidence at `7df55aa7fd91662470ab2fcc1bff5909aff79c5b` (PR201), without
treating it as merged evidence. It validates the actual source-specific records,
not equivalence of all current SDK runtime paths to those old qualified commits.

`consumer-ac4cade/` retains the fresh independent module-consumer run for
`ac4cade4c93fdfd4214c2e5acf9397676daf53b5`, whose SDK Go/module bytes equal
the main baseline `0cab072e56a3c60e8a7c3a9a17b5c52fde2cb898`.
`candidate-go-module-identity.json` independently confirms all **876** raw
committed Go/module blobs are also unchanged at the audit's later commit.
No Go source/module changes were introduced by this audit.

The module ZIP contains all **4312** intended committed files, including all
**278** third-party files. `source-manifest.json` hashes every raw committed file.
The fresh consumer cache downloaded that exact ZIP; the harness checked each
downloaded byte and every compiled SDK import's module/path boundary. Its
SHA256 is `9b6b1e92b064f28a4a46e2c1d6274fca8d36b7def65ff2326ef58c839629cc6a`.
Canonical ZIP creation used isolated `golang.org/x/mod v0.43.0`; the SDK's own
go.mod and dependency graph were unchanged. The exact executed harness, helper
and template are retained under `consumer-ac4cade/executed-tool-sources/`, with
their hashes in `report.json`. The fully generated public consumer source is
`executed-consumer_test.go.txt`. Later template formatting and preflight guard
hardening are not relabeled as having executed in this earlier run.

Go **1.27.4**, Windows/amd64 executed the public consumer's secure-configuration,
redaction and portable descriptor/conditional tests. The six Windows/Linux/macOS
amd64/arm64 binaries were **cross-built**, not all executed. In particular,
Linux/macOS/arm64 execution or live AD acceptance is not claimed. Local logs and
binary hashes distinguish host execution from compilation.

`windows-full-tests.log`, `windows-vet.log` and `required-lint.log` retain the
normal checkout validation on this branch. They are local checks, not a claim
that those test binaries were compiled from an independently frozen raw-Git
archive. The separate consumer run supplies that canonical source boundary.
`python-tests.log` records the14 offline adversarial guards; the deliberate
duplicate-ZIP fixture warning is expected. Raw downloaded-module resolution
logs and binaries remain in the private local verification directory; public
reports retain their counts/hashes without publishing local account/cache paths.

`artifact-hashes.json` covers the retained report/log/source bytes. The enclosing
`.gitattributes` rule disables text conversion, and those hashes are checked
against the committed Git blobs before publication. Hash consistency is evidence
integrity, not independent authentication of the lab observer or authorization
to declare the SDK/provider release qualified.
