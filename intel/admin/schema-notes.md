# Admin Schema Notes

## Pending Approval Entry

Use JSON Lines so admin tools can append one reviewed candidate at a time.

```json
{"kind":"file_hash","scope":"site","site_id":"example.com","path_hint":"wp-content/plugins/custom/plugin.php","sha256":"...","md5":"...","reason":"Known custom plugin","requested_by":"server01","created_at":"2026-06-20T00:00:00Z"}
```

## Promotion Guidance

- Promote to `whitelists/sites/SITE_ID.json` when the file/process/cron is specific to one site.
- Promote to `whitelists/global/` only when it is known-good across the fleet.
- Prefer expiry dates for temporary operational exceptions.
- Never promote a suspicious item directly from an active incident without independent review.
