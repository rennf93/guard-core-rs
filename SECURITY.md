Security Policy for guard-core-rs
==================================

Supported Versions
------------------

We provide security updates for the following versions of `guard-core-rs`:

| Version | Supported     |
| ------- | ------------- |
| 0.0.x   | Supported     |

Once the crate reaches 1.0, security support will be extended to the current
and immediately previous minor versions.

Reporting a Vulnerability
-------------------------

We take the security of `guard-core-rs` seriously. If you believe you've
found a security vulnerability, please follow these steps:

1. **Do not disclose the vulnerability publicly** until it has been addressed
   by the maintainers.
2. **Report the vulnerability through GitHub's security advisory feature**:
   - Go to the [Security tab](https://github.com/rennf93/guard-core-rs/security/advisories)
   - Click "New draft security advisory"
   - Fill in the details and submit

   Alternatively, use [GitHub's private vulnerability reporting](https://github.com/rennf93/guard-core-rs/security/advisories/new).

3. Include the following information:
   - A description of the vulnerability and its potential impact
   - A minimal reproduction (Rust snippet or test)
   - Affected versions
   - Any potential mitigations or workarounds

Maintainers will acknowledge your report within 48 hours and provide a
detailed response within 7 days, including next steps.

Security Best Practices
-----------------------

When using `guard-core-rs` in your applications, consider the following:

### Configuration

1. **Secrets**: Store MaxMind tokens, agent API keys, and Redis URLs via
   environment variables or a secrets manager; never hard-code them.
2. **Whitelist and Blacklist**: Review and update IP whitelists / blacklists
   regularly.
3. **Rate Limiting**: Set `rate_limit` and `rate_limit_window` to values
   appropriate to your application's capacity.
4. **Auto-Ban**: Configure `auto_ban_threshold` and `auto_ban_duration`
   based on your threat model.
5. **Country Blocking**: Only enable `blocked_countries` /
   `whitelist_countries` when you have a compliance or security reason.
6. **HTTPS Enforcement**: Set `enforce_https = true` in production.
7. **CORS**: Follow least privilege — explicit `cors_allow_origins`, no
   `"*"` with credentials.

### Redis

If you enable `redis-support` for distributed state:

1. Require Redis authentication with a strong password.
2. Bind Redis to localhost or an internal network; never expose it to the
   internet.
3. Use TLS (`rediss://`) for connections in production.
4. Keep Redis updated.

### Logging and Monitoring

1. Configure log rotation for `custom_log_file` if set.
2. Review security logs regularly.
3. Alert on unusual patterns detected by the pipeline.

### Dependencies

1. Keep `guard-core-rs` and its dependencies updated — `make upgrade`.
2. Run `cargo audit` / `cargo deny` as part of CI (see our
   `.github/workflows/ci.yml` for a template).

Security Features
-----------------

`guard-core-rs` provides the following defensive capabilities:

- IP whitelisting and blacklisting (CIDR + exact)
- User-agent filtering (regex patterns)
- Rate limiting (sliding window, Redis-backed or in-memory)
- Automatic IP banning with TTL cache + Redis persistence
- Penetration-attempt detection with ReDoS-safe pattern compilation
- Country-based access control via MaxMind GeoIP2
- Cloud-provider IP blocking (AWS / GCP / Azure)
- Per-route overrides via `SecurityDecorator` + `RouteConfig`
- HTTPS enforcement with proxy trust
- Security headers (HSTS, CSP, X-Frame-Options, etc.)

See [the rustdoc](https://docs.rs/guard-core-rs) for API details.

Threat Model
------------

`guard-core-rs` is designed to protect against common web-application threats:

- Brute force attacks
- Distributed denial-of-service (DDoS) — limited; see your load balancer
  for volumetric protection
- Web scraping and data harvesting
- Reconnaissance from known malicious IPs
- Basic penetration testing attempts (SQL injection, XSS, path traversal,
  command injection patterns)

This crate is a defense-in-depth measure. It should be used alongside proper
authentication, authorization, input validation at application boundaries,
and output encoding.

Security Updates
----------------

Security updates are released as needed. Subscribe to GitHub releases to be
notified.

Responsible Disclosure
----------------------

We follow responsible disclosure principles:

1. We confirm receipt of your vulnerability report
2. We provide an estimated timeline for a fix
3. We notify you when the vulnerability is fixed
4. We publicly acknowledge your disclosure (unless you prefer to remain
   anonymous)

License
-------

`guard-core-rs` is dual-licensed under MIT or Apache-2.0 at your option. See
[LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE).
