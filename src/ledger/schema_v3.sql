-- Ledger schema, version 3.
--
-- `artifacts.tag_override` keeps the digest-qualified tag of an artifact that
-- lost its descriptive tag to a different upstream file. Which reference an
-- artifact uses follows from the other artifacts of the same crawl, so the
-- ledger cannot derive it again on a round trip; without the column, `verify`
-- and `repair` would address the other file's tag.

ALTER TABLE artifacts ADD COLUMN tag_override TEXT;
