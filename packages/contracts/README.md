# Shared contracts

The envelope (1.0), parser report (3.4), catalog (0.1-draft), CASPER database migration (5), run manifest (1.0), and run event (1.0) have independent versions. A storage migration is not a module wire-protocol change. Removing required fields or changing their meaning requires a new contract version and an explicit adapter. Security-sensitive action objects continue to reject unknown fields.

Initial manifests are immutable. Runtime facts and model-call records are separate observations. Missing legacy provenance is unavailable; the importer never infers a historic SHA from the current checkout. Raw observations are verified before comparison normalization. Persistence and HTTP serializers redact credentials without removing numeric token usage.
