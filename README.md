# Dofus key finder

Recover repeating XOR keys from Dofus map data:

```sh
go run ./cmd/dofus-key-finder
```

The command first recovers keys uniquely determined by the cell constraints. It then trains a simple character-frequency model from imported and exact keys and predicts the remaining unknown keys. The model scores characters separately at each of the ten cell positions and only selects bytes allowed by the deterministic solver. Incompatible training keys are reported and skipped; predictions never train the model. Without training data, ambiguous keys remain unresolved.

| File | Contents |
| --- | --- |
| `data/maps.csv.gz` | Gzip-compressed source map data. |
| `data/keys_imported.csv` | Externally sourced keys, preserved unchanged. |
| `data/keys_exact.csv` | Unique deterministic recoveries, including imported matches. |
| `data/keys_predicted.csv` | Statistical predictions; may be incorrect. |
| `data/maps_metadata.csv` | Incomplete map metadata, retained for future use. |

Key inventories use `id,date,key`. ID and date together identify a map version; keys retain their escaped, hex-encoded representation. Imported and exact inventories may overlap, but predictions must not overlap either. Duplicate map versions within an inventory are rejected.

Deterministic recoveries promote previous predictions to the exact inventory. Differing predictions and conflicts with imported keys are reported; imported values remain unchanged. Predictions for unresolved unknown maps are refreshed when training data is available. Existing predictions for maps absent from the input or lacking recovery/training data are preserved. Coverage counts the union of imported and exact versions, excluding predictions. “Exact” means unique under the solver's current constraints.

Override paths with `--maps-file`, `--imported-keys-file`, `--exact-keys-file`, and `--predicted-keys-file`. Map input supports plain `.csv` and gzip-compressed `.csv.gz` files.

Evaluate the model on grouped held-out imported/exact keys without updating inventories:

```sh
go run ./cmd/dofus-key-finder --evaluate
```

Evaluation keeps versions of a map ID and identical plaintexts together in a fixed 60/20/20 train/validation/test split. It reports whole-key and unresolved-byte accuracy. Conflicting or incompatible labels fail evaluation. This partition has been inspected in earlier experiments, so results are a regression benchmark rather than a fresh estimate of generalization.

The `decrypt.Key(map, model)` API returns a result with `Key`, `UsedPrediction`, and `Stats`: key length, encrypted byte count, determined/ambiguous key-byte counts, and the exact candidate count as a decimal string. Passing a nil model requests deterministic recovery only; `ErrAmbiguous` retains candidate statistics. These statistics are not calibrated confidence values.

Run checks with `go test ./...`. The map data is included; Git LFS is not required.
