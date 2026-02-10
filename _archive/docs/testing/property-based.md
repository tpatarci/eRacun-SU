# Property-Based Testing Playbook

The archive-service and digital-signature-service now rely on shared generators and property suites to assert system-level
invariants that cannot be exhaustively enumerated with examples alone. This guide describes the generators, the properties they
exercise, and how the suites are wired into CI.

## Shared generators (`shared/testing/property-generators.ts`)

| Generator | Purpose |
| --- | --- |
| `invoicePropertyArb` | Emits randomized but schema-faithful UBL invoices (XML + base64, issue dates, totals, submission metadata). |
| `certificateMetadataArb` | Produces issuer/subject distinguished-name fragments, serial numbers, and validity windows for XMLDSig certificates. |
| `payloadDigestArb` | Emits opaque byte buffers paired with a deterministic SHA-512 digest for checksum scenarios. |

The arbitraries sanitize XML and DN fragments so they can be injected directly into fixtures without risking parsing errors. The
module exports both the arbitraries and their TypeScript interfaces so services can construct strongly-typed commands.

## Archive-service invariants

`tests/properties/archive.validators.property.test.ts` encodes five compliance properties that every archive validator must hold
for all generated invoices:

1. **Payload round-trips** – Whatever is stored in WORM storage must be bit-identical to the decoded base64 payload retrieved later.
2. **Deterministic hashing** – The SHA-512 digest computed by `ArchiveService` must equal the digest computed independently for the same payload and remain stable across idempotent replays.
3. **Duplicate tolerance** – Replaying the exact same invoice must behave idempotently, returning the previously persisted metadata.
4. **Duplicate rejection** – Mutating the payload while reusing the same invoice ID must be rejected with a conflict to enforce immutability.
5. **Checksum enforcement** – The WORM adapter refuses to persist content when the provided digest does not match the payload and can always verify stored objects via `verifyIntegrity`.

These properties collectively verify checksum validation, immutability enforcement, and payload fidelity.

## Digital-signature-service invariants

`tests/properties/signature.property.test.ts` covers the XMLDSig and ZKI layers with the following properties:

1. **Canonicalization stability** – Signing the same XML twice yields byte-identical envelopes that explicitly advertise the configured canonicalization algorithm.
2. **Valid payload acceptance** – Random invoices signed with the test certificate always verify successfully after canonicalization.
3. **Tamper rejection** – Any mutation of signed fiscal amounts triggers signature verification failures with surfaced errors.
4. **ZKI idempotency & sensitivity** – Identical fiscal parameters always return the same ZKI code, while any perturbation (e.g., total amount) produces a different hash.
5. **Certificate metadata fidelity** – Parsing randomized certificate metadata preserves subject/issuer ordering, serial numbers, and validity windows.

## Running the suites

- Per service, run `npm run test:properties` to execute only the property suites (Jest + fast-check).
- At the repository root, `npm run test` (and CI) now invoke deterministic suites **and** the property suites for every service that exposes a `test:properties` script. To run just the property suites across all services use:

```bash
SERVICE_TEST_MODE=properties npm run test:all
```

CI fails immediately if any property shrinks to a counter-example. Keep the properties deterministic (no timers or randomness outside fast-check) so they remain reproducible under shrinking.

## Coverage expectations

Property suites execute under Jest, so their executions appear in `coverage/coverage-summary.json` when running `npm run test:coverage`. Use these reports to confirm that the properties hit integrity branches (e.g., duplicate handling, tamper detection) that previously lacked explicit protection.
