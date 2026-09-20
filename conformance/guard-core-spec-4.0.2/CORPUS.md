# Vendored Conformance Corpus: guard-core-spec-4.0.2

Byte-identical copy of the reference fixture corpus from
[guard-core](https://github.com/rennf93/guard-core) at
`specs/fixtures/cases/`, reference commit
`886f801332e4056b1e44561886e638f8017374eb` (matches `index.json`
`engine_commit`), spec_version 4.0.2, 11 suites, 163 cases.

Do not edit the vendored files. Corpus updates land by re-vendoring from the
reference repo and bumping the spec pin deliberately (conformance drift
discipline: port CI stays red until the port implements the new behavior).

## sha256 manifest

```
48c36e1c85d5ad1eadfd7c32fc4b26c3118c39039df7762373e18bb11bff2dce  cases/benign.json
755135bddf9ae39b01247c20b346210f480c629ccb4a4cdc85eb2a6f7025cf22  cases/boundaries.json
b034e19bef84e8d3244d4d3b907d8acc407025322109aeaf1afcedda811f07ba  cases/cmd_injection.json
f661d5ebfa867dd8a78798e7fa024b846b82976b6107ea96abc783c55cb273ce  cases/context_matrix.json
cf96ef64d6bbb9647c368ba793be2d33b635eb1cdd884322fd6fa7c50adeefe5  cases/encoding.json
48adaeaca7ba4c54d9ce5e12cc8f17e4be9e8aab7cb4899603bae379bb5a4325  cases/inclusion_sensitive_recon.json
ecb691e6a490e8ea7f2c9a07e69601f5f96df6f77dbb013842d19f8f6c2f9daf  cases/index.json
87f32109c1ad2eaa1deaf3b8f0848e6e03a016d8d542bc87d3593f56f6cfb363  cases/misc_injection.json
784211f63d2bdc23b3dc18a2e3a27e8d3377402f2936243cd718866fdb2d3d37  cases/path_traversal.json
85e78245fe53d72e2abba36e64bb79801cc638a8aca39cd6700269e2601f0fb0  cases/semantic.json
753f2e0ad9ed0f324c005544225ace3e8fab16d1c34f9b1f1b01b7e6a65092fb  cases/sqli.json
d0b427179ca19202b2eff15b6f8021196639c5e66bcf1a74fd9696a3844e6a57  cases/xss.json
```

Comparison rules are normative and live in the reference repo
(`specs/fixtures/README.md`): canonical threat sort
`(category, pattern, position, type)` compared order-insensitively,
`execution_time` and other timing-derived fields excluded, floats at
6-decimal precision, `processed_length` mandatory, `spec_version` verified
on load.
