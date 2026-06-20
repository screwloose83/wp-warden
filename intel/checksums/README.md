# Checksums

Checksum maps live here.

Keep WordPress official MD5 values when required for official comparison, but include SHA-256 for local baselines and custom package trust where possible.

Suggested component schema:

```json
{
  "schema": "wp-warden.checksums.component.v1",
  "type": "plugin",
  "slug": "example-plugin",
  "version": "1.2.3",
  "source": "clean vendor ZIP",
  "created_at": "2026-06-20T00:00:00Z",
  "files": {
    "example-plugin.php": {
      "md5": "...",
      "sha256": "..."
    }
  }
}
```
