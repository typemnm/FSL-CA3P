# Shared contracts

The envelope (1.0), parser report (3.4), catalog (casper-attack-catalog-1), CASPER database migration (7), run manifest (1.0), and run event (1.0) have independent versions. A storage migration is not a module wire-protocol change. Removing required fields or changing their meaning requires a new contract version and an explicit adapter. Security-sensitive action objects continue to reject unknown fields.

CASPER's optional `casper-parser-locations-1`, `casper-check-results-1`, and `casper-reference-1` contracts carry observed input locations, verifier results, and preserved review context respectively. Their field definitions and JSON schemas are maintained in `casper-db/`. Existing parser and XSS history payloads remain supported.

`casper-knowledge-query-1` accepts one target's parser locations and `casper-software-inventory-1` without requiring CVE IDs. The read-only `casper-knowledge-context-1` response combines prior ready cases with exact-product advisory candidates and per-inventory applicability evidence. The adapter exposes it as optional `knowledgeContext` when `softwareInventory` is supplied. Stored-advisory coverage and truncation are explicit. A shared SQLite file preserves separate Case/advisory namespaces; it does not change the envelope or existing Case migration version.

Initial manifests are immutable. Runtime facts and model-call records are separate observations. Missing legacy provenance is unavailable; the importer never infers a historic SHA from the current checkout. Raw observations are verified before comparison normalization. Persistence and HTTP serializers redact credentials without removing numeric token usage.

The retired `pentest-db` module has no independent catalog or store. New storage/catalog envelopes address `casper-db`; the old receiver and import names are compatibility aliases. `casper-attack-template-1` registers draft executor contracts bound to an immutable pattern revision and its verification rule IDs. Registration never enables execution. Historical disk artifacts retain their old location/reader to preserve existing evidence.
