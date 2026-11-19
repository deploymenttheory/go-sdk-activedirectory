# Corrected forwarding interoperability and offline checks

Actual corrected source `075026493693067e0b0c8daf3b686a699c4cb3ca`, Go 1.27.4
Linux/amd64. The independent installed MIT GSS library accepts both the default
nondelegating and explicit forwarding AP-REQs. It validates actual GSS identity,
delegated credential flags/profile/expiry and imports the credential into an
owned MEMORY cache without the SDK's ASN.1 decoder. The owned SDK LDAP peer
separately completes mutual/SASL/final acknowledgement. This is an offline
protocol gate, not MIT LDAP-server or live AD qualification.

Original d8 and diagnostic271 runs passed the default control but failed real
forwarding. Independent standard DER parsing exposed an unset explicit [2]
ticket-container tag; the owned RawValue decoder had accepted its own malformed
encoding. The correction emits [2] and rejects the wrong tag. Original failed
logs and their exact source manifests remain unchanged here.

The corrected worker's focused MIT test passed, but its subsequent full-suite
execution was interrupted without a terminal result. Root verified there was
no active Go process. Its first recovery stopped before tests because the old
temporary extraction was absent; that failed preflight is also retained. Root
then independently verified all 4,325 ZIP inputs against raw Git, extracted a
fresh owned Linux snapshot, and completed the full race suite plus vet with
actual terminal0. All 4,325 source bytes remain unchanged before/after testing.
The invocation receipt binds the executed source and log hashes.

All keys/tickets are synthetic owned offline fixtures. No live directory,
account grant, lab SSH call or user credential operation occurred. Executables,
credential payloads and private fixture material are excluded from these public
records. `artifact-hashes.json` indexes byte-preserved originals.

Full SDK12 completion remains pending: same-forest second-domain/RID fixtures,
real delegated source/destination execution, user/computer password preservation,
refusal/uncertainty/cleanup and applicable Windows/Linux server-profile evidence.
Missing infrastructure is not counted as unsupported or passing.
