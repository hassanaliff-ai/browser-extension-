# Database operations

Core tools: `backup`, `restore-test`, `migrate`, `benchmark`, and `export` in `scripts/database_ops.py`.

Backups and restoration use private local configuration. Migration versions are applied in order within a transaction. The ledger prevents duplicate execution; source-file checksum comparison has been removed. Rollback remains limited to disposable test databases.

Export allows only domain evidence and scan summaries, using bounded date ranges and row limits. Credentials, sessions and account secrets cannot be exported. Domain export follows the configured privacy rules. Existing output files are never overwritten.

Advanced database monitoring, scheduled monitoring maintenance and domain imports have been removed. Structural checks in `scripts/check_database.py` remain available to verify schema integrity and runtime permissions.
