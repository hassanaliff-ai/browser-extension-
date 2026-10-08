# ExtSecure 0.8.7: table size repair

Table controls now save directly in Chrome local storage and apply density immediately. Older running workers that omit tableSize no longer reset the choice. Reopening the console restores the saved density; other open console pages update through storage notifications. Settings and theme changes retain the selection. Storage errors are surfaced instead of confirming a failed save. No API or database changes are required.

Validation on 8 October 2026:
- 189 automated extension tests passed, including persistence with an older worker, storage failures, and local change notification scope.
- Isolated headless Chrome rendered the real console assets using synthetic event data and a worker double that discarded tableSize. Compact, Standard and Spacious measured 66.28, 88.39 and 156.50 pixels per sample row.
- Twelve layout combinations passed: English/Arabic, light/dark, and all three densities. Reload persistence, cross-tab synchronization, Settings selection, absence of horizontal page overflow, and all twelve records remaining visible were checked.
- ZIP validated: 30 runtime assets, manifest version 0.8.7; every archived file matched the source SHA-256 and ZIP CRC verification passed.

The browser checks used an isolated test profile, not the user's authenticated Chrome profile or live threat data. Reload the unpacked extension in chrome://extensions and reopen its console to load the new UI module.
