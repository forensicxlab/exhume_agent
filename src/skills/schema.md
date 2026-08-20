## Database Schema

### system_files — indexed filesystem entries
Columns: `id`, `evidence_id`, `partition_id`, `identifier`, `absolute_path`, `name`, `ftype`, `size`, `created`, `modified`, `accessed`, `permissions`, `owner`, `group`, `display`, `path_key`, `parent_path_key`, `depth`, `is_dir`, `sig_name`, `sig_mime`, `sig_exts`, `anomaly_flag`, `host_path`, `metadata`

Key semantics:
- `identifier` — the `file_id` consumed by every tool (`extract_file`, `delegate_*`). Always use this, not `id`.
- `ftype` — `'File'` or `'Directory'`; `is_dir` is 1/0 equivalent.
- `absolute_path` — logical forensic path inside the evidence (e.g. `/Windows/System32/cmd.exe`). Use for pattern matching and artifact path lookups. **Not** a valid host path.
- `host_path` — real path on the host filesystem (e.g. `/cases/EVIDENCE/Windows/System32/cmd.exe`). **Always** use this for `shell` commands. `NULL` for disk image partitions.
- `sig_name` / `sig_mime` / `sig_exts` — magic-byte file type, populated after identification runs. May be NULL — fall back to filename heuristics (`LOWER(name) LIKE '%.exe'`).
- `anomaly_flag = 1` — extension does not match magic-byte signature. **High-priority forensic indicator — check this first.**
- `created` / `modified` / `accessed` — Unix epoch seconds. Use the `timeline` view for cross-event temporal queries.
- `metadata` — JSON blob with filesystem-specific extended attributes (MFT attributes, APFS xattrs, Linux xattrs, etc.).

### artifacts — recognized forensic artifact matches
Columns: `id`, `evidence_id`, `file_id`, `partition_id`, `name`, `description`, `parser`, `tag`, `category`

- `category` values: `system`, `network`, `users`, `application`, `media`
- `tag` values: `logs`, `persistence`, `registry`, `execution`, `history`, `browser`, `security`, `filesystem`, `memory`, `user_activity`, `network`, `media`, `communications`, `packages`, `device`, `accounts`, `jobs`, `config`
- Query by category/tag to find artifact classes: `SELECT * FROM artifacts WHERE tag = 'persistence'`

### artifact_objects — parsed artifact content
Columns: `id`, `evidence_id`, `partition_id`, `artifact_id`, `file_id`, `parser`, `kind`, `text`, `json`, `created_at`

- `parser` — producer of the record (e.g. `windows_evtx`, `windows_pe`, `mobile_ios_imessage`, `mobile_ios_whatsapp`, `ai_specialist`)
- `kind` — record type within parser output (e.g. `event`, `module`, `message`, `record`, `entry`)
- `text` — human-readable summary; `json` — full structured data
- **Always query here before delegating** — cached under `parser = 'ai_specialist'`:
  `SELECT file_id, kind, text FROM artifact_objects WHERE parser = 'ai_specialist' AND file_id = ?`
- Inventory parsed data: `SELECT parser, kind, COUNT(*) FROM artifact_objects GROUP BY parser, kind`

### partitions
Columns: `id`, `evidence_id`, `kind`, `first_byte_addr`, `size_sectors`, `sector_size`, `size_bytes`, `fvek`, `description`
- `kind`: `mbr`, `gpt`, `logical`, `folder`
- `fvek` — BitLocker Full Volume Encryption Key (hex) if unlocked

### investigation_notes — persistent notepad
Columns: `id`, `file_id`, `path`, `note`, `significance`, `created_at`
- Save with `save_investigation_note`. Retrieve: `SELECT * FROM investigation_notes ORDER BY significance DESC`

### artifact_attachment_refs — messaging app media cross-references
Key columns: `parser`, `app`, `local_path`, `remote_url`, `kind`, `mime`, `file_name`, `file_size`, `resolved_file_id`, `resolved_host_path`, `preview_base64`
- Populated by messaging parsers (iMessage, WhatsApp, Signal, Telegram, Messenger).
- `resolved_host_path` — direct host path to the attachment when resolved; use for `shell` or `extract_file`.

### Views

**timeline** — unified filesystem timestamps across all files
Columns: `evidence_id`, `partition_id`, `row_id`, `identifier`, `absolute_path`, `host_path`, `name`, `sig_name`, `anomaly_flag`, `event_type` (`'created'`|`'modified'`|`'accessed'`), `event_time` (ISO string), `ts_unix` (integer)
Temporal correlation: `SELECT * FROM timeline WHERE ts_unix BETWEEN 1700000000 AND 1710000000 ORDER BY ts_unix`

### Full-text search
If `system_files_fts` exists, use FTS5 for fast keyword search over all paths and filenames:
`SELECT * FROM system_files_fts WHERE system_files_fts MATCH 'password'`
