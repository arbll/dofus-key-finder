# Dofus key finder

Recover repeating XOR keys from Dofus map data:

```sh
go run ./cmd/dofus-key-finder
```

The CLI reads `data/maps.csv` (stored with Git LFS) and three key inventories:

| File | Contents |
| --- | --- |
| `data/keys-imported.csv` | Externally sourced keys, preserved when confirmed or in conflict with recovery. |
| `data/keys-exact.csv` | Keys uniquely recovered under the deterministic solver's current constraints. |
| `data/keys-predicted.csv` | Statistical model predictions without a deterministic guarantee; initially empty. |

All inventories use `id,date,key`. Map ID and date together identify a map version. Keys retain the existing escaped, hex-encoded format. Imported and exact inventories can overlap: the exact inventory contains every deterministic recovery, including imported keys. Predictions must not overlap either inventory. Duplicate map versions within a file are rejected.

All deterministic recoveries go to the exact inventory, including recoveries that confirm or conflict with an imported key. Imported values remain unchanged; conflicts are reported. If a predicted map version is recovered exactly, its prediction is removed and the recovered key is added to the exact inventory. A differing prediction is reported. Imported keys stay in the imported inventory even when confirmed. Coverage counts the union of imported and exact map versions once; predictions are reported separately.

Override paths with `--maps-file`, `--imported-keys-file`, `--exact-keys-file`, and `--predicted-keys-file`. The former `--keys-file` option and merged `data/keys.csv` have been replaced by these three inventories.

Run checks with `go test ./...` after fetching the map data with Git LFS.
