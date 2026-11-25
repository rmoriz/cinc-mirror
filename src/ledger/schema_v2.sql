-- Ledger schema, version 2.
--
-- `artifacts.raw_arch` keeps the upstream architecture spelling. The public
-- `arch` is mapped (`x86_64` -> `amd64`), and the OCI metadata layer is
-- published byte-for-byte from the upstream document, so a ledger round trip
-- must restore the raw value rather than approximate it from `arch`.

ALTER TABLE artifacts ADD COLUMN raw_arch TEXT NOT NULL DEFAULT '';
