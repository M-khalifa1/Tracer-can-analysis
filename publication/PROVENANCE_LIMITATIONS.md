# Remaining experimental provenance and release limitations

1. Original `results/archived_strict_audit.json` reports `FAIL` for the historical
   **literal A5 replay** requirement, correctly so: the archived physical
   experiment used crafted valid-MAC stale sequences. `results/archived_claims_reconciled.json`
   reports the qualified, narrower interpretation. Both are retained.
2. The HMAC benchmark JSON's `platform` field literally contains `FILL_ME`.
   Original CPU/compiler identity and individual timing samples were not preserved.
   The numerical values may be plotted as an existing host benchmark summary;
   do **not** claim an exact distributional reproduction or verified host identity.
3. All physical experiments are from one robot/campaign; no new physical
   replication, embedded microcontroller benchmark, live IDS latency or active
   gateway enforcement was performed during this revision.
4. Data/code availability is contingent on submitting this full ZIP.
5. The original source contains a fixed experimental MAC test key and attack
   generation utilities. The release is for controlled scientific verification;
   it does not implement production-grade secure key management or command
   path isolation.
6. Publication authenticity (reviewer response, manuscript references, grant
   acknowledgment, author authority to publish code/logs) still requires owner
   sign-off. Code is MIT-labelled in the source, but that does not itself resolve
   ownership/consent for every experimental artifact or third-party image.
