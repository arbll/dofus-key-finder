| File | Purpose |
| --- | --- |
| `maps_metadata.csv` | Incomplete world coordinates and area hierarchy, merged by map ID. |
| `maps.csv.gz` | Gzip-compressed source map data. |
| `keys_imported.csv` | Keys from external sources. |
| `keys_exact.csv` | All keys recovered by the deterministic solver, including imported matches. |
| `keys_predicted.csv` | Model predictions; may be incorrect. |
| `keys_merged.csv` | Final keys, merged by map ID and date with priority Exact → Imported → Predicted. |

The imported, exact, and predicted CSV key files use `id,date,key`. ID and date identify a map version; keys are escaped and hex-encoded.

`keys_merged.csv` is regenerated on each normal run with columns `id,date,key,source`, sorted by numeric ID then date. The `source` column is `merged` for exact solver keys, `imported` for external keys, or `predicted` for predictions. Dates preserve leading zeros, and keys retain their original encoding. Evaluation (`-evaluate`) leaves all files unchanged.
