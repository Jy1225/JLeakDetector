# Soot Bridge Notes

RepoAudit now supports loading `soot_facts.json` via:

- `--enable-soot-prefilter`
- `--soot-facts-path <path>`

This folder is reserved for an external Soot bridge jar that exports facts in a
JSON format consumable by `src/tstool/validator/java_soot_prefilter.py`.

## Expected invocation contract

Bridge main class should support:

```text
--input-dir <compiled class dir>
--classpath <analysis classpath>
--output <soot_facts.json path>
```

The run script can auto-generate facts before scanning by setting:

```bash
ENABLE_SOOT_PREFILTER="true"
AUTO_GENERATE_SOOT_FACTS="true"
SOOT_FACTS_MODE="bridge"
SOOT_BRIDGE_JAR="/path/to/soot-bridge-all.jar"
SOOT_FACTS_PATH="/path/to/soot_facts.json"
```

If no bridge jar is provided, `SOOT_FACTS_MODE="auto"` falls back to a
Tree-sitter-based generator (`ts-fallback`) for compatibility testing.
