# Vendored Conformance Corpus: guard-core-spec-4.0.3

Byte-identical copy of the reference fixture corpus from
[guard-core](https://github.com/rennf93/guard-core) at
`specs/fixtures/cases/`, reference commit
`436d6f720e506510c8b7b9fafef095c7335b6ba8` (the 4.0.3 release commit,
matches `index.json` `engine_commit`), spec_version 4.0.3, 12 suites,
186 cases.

The corpus was regenerated at spec 4.0.3 from the reference generator with
one new suite, `binary_bodies.json`: binary-body vectors for the 4.0.3
noise gate (upstream commit 436d6f72, released 2026-09-21). The payload
classes are taken verbatim from the payload constants in the reference
honesty suite (`tests/test_sus_patterns/test_pattern_binary_noise_gate.py`)
so every port generates byte-identical vectors:

- `binary_benign_*`: benign binary blobs (random noise in the latin-1 and
  lossy-decoded views, a zip upload, control-byte runs) that 4.0.2 wrongly
  blocked and 4.0.3 must pass
- `binary_attack_noise_prone_*`: noise-prone pattern matches inside
  artifact-dense binary content that the gate must discard
- `binary_attack_*`: attacks hidden in binary padding (padded webshell,
  pickle opcode stream, base64-fragmented multipart part) that must still
  be caught (signature patterns are never gated)
- `binary_text_*`: pure-text, accented, and non-Latin controls, unchanged

The corpus stores text as valid Unicode: the reference's surrogateescape
decode view is mapped to the lossy representation (undecodable bytes
become U+FFFD, an artifact class in every port) by a deterministic
transform, documented in the reference generator.

Do not edit the vendored files. Corpus updates land by re-vendoring from the
reference repo and bumping the spec pin deliberately (conformance drift
discipline: port CI stays red until the port implements the new behavior).
The normative `specs/fixtures/` directory in guard-core remains on-disk-only
per repo convention.

## sha256 manifest

```
070ef1f9b4f3ee11c707ae30a27a96915edbe8f27c2800c8588b31d3feb2902f  cases/benign.json
2171d675878c9bf8f86662e88fc8e5e382a171aa18847fca1f023d16ddc792e9  cases/binary_bodies.json
8e0726f7a980baa583faf2fdd5cdf8e81b9592b13025ca655cf46d8bff6bb30e  cases/boundaries.json
8240c4532e74af8a9c97355732c79a3ebf2a9c312ec66a42e9f7cce0d59ca4cb  cases/cmd_injection.json
c816840563ad9cd5ac7f0d8c83cc588f1867a84e05eec1fc76fc8f8e0b4c10ed  cases/context_matrix.json
bc5a301f4222d3892fc99aeed6afdcb1f9ef450ce032c09597cadf8a604eb168  cases/encoding.json
08e71c1eb5d0e69272dd3ac11f7ea26aee2a5768e280d893affd97fea6988a16  cases/inclusion_sensitive_recon.json
50f9f196c516b9a1a6cc2145df7fd7894ca6efc55afdb2a059e3de3f80e399f6  cases/index.json
1e62cc5e9671b0bc223ab4490cea6d4a731b4d7c43edf0ea396aeb8249622086  cases/misc_injection.json
88a7ecc79f8a07153d5e5a01d2da308e1d4d10af7373f4d7fda770a5f6c2d760  cases/path_traversal.json
6115655b2ba921c63dc335986c33ac8652652c07c9987b95461de619c112cd2c  cases/semantic.json
d922c9e46a6a4ae5bd9aee5839f23c645b4a1759c2d428b6e317bd12a6f1070d  cases/sqli.json
753fd59a2fd50f9282c79910714288ada14bc532bf3016bc03002731cc560667  cases/xss.json
```

Comparison rules are normative and live in the reference repo
(`specs/fixtures/README.md`): canonical threat sort
`(category, pattern, position, type)` compared order-insensitively,
`execution_time` and other timing-derived fields excluded, floats at
6-decimal precision, `processed_length` mandatory, `spec_version` verified
on load.
