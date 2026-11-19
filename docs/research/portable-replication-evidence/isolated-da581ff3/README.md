# Isolated packet, record and diagnostic decoder proof

This snapshot is **not adopted SDK source** and does not enable portable RPC.
Its synthetic peers start with copied record keys. It does not qualify Kerberos
authentication, RPC binding, endpoint mapping, DRS operations or Active Directory.
The later raw DCE authentication prototype is not included in this snapshot.
The full SDK-07 objective remains tracked by #172.

The preserved candidate tests first demonstrated malformed fragment/authentication
length handling and accepted unexpected record sequence/header fields. Additional
canonical DRS decoder tests accepted inconsistent container counts and invalid
UTF16. The raw failure logs and canonical fixture producers are retained here.

The proposed patch fixes the used packet/record paths and adds a serialized
protected stream plus a bounded NDR32 decoder for the four diagnostic reply arms.
Actual `net.Pipe` tests exercise fragmentation, tamper/replay/truncation, verified
prefixes, authenticated faults, poisoned-session reuse and cancellation retirement.
Canonical upstream-encoded NDR stubs cover neighbors, connection/link failures and
pending operations. Null strings remain distinct from non-null empty strings.
Separate Python/PyCryptodomex AES 17/18 records and MICs match both sender roles;
their primitive implementation also checks published n-fold and CTS vectors.
Profiles 19/20 are explicitly refused without fallback.

Windows Go 1.27.4 tests/vet and an independently executed Linux Go 1.27.4 race run
passed. The source manifest hashes every one of the 265 actual snapshot inputs;
the ZIP also contains that manifest. All Go source fits 180 columns. The NDR fuzzer
completed 848,846 cases in 10 seconds; that count was observed in tool output, whose
raw stdout was not saved. It is not represented as a retained raw execution log.

`proposed-source.patch.txt` is review/reconstruction text, not compiled SDK code.
Apply it within the selected upstream source closure named by
`upstream-source-map.json`, restore the proposed module manifests and copy the
retained fixtures into their corresponding `3rd_party/msrpc` paths. The copied
GoKrb files come from SDK commit 95e116e. Their actual build bytes in this snapshot
have CRLF endings; `gokrb-source-relation.json` proves equality with canonical Git
contents after LF normalization, with no substantive changes. It does not claim
raw working-tree/Git byte identity. The original ZIP remains immutable locally.

Run `go test -mod=readonly ./3rd_party/msrpc/... -count=1` and
`go vet -mod=readonly ./3rd_party/msrpc/...`; add `-race` with a supported compiler.
Before any adoption, the final used-code closure must exclude unused upstream
multiplexing/provider machinery, pass required lint and complete actual per-stage
authentication and RPC/DRS qualification. The live Windows/Linux × Server 2016,
2019, 2022 and 2025 matrix remains a separate required gate.
