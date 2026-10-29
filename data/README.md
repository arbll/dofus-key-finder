| File | Purpose |
| --- | --- |
| `maps_metadata.csv` | Incomplete world coordinates and area hierarchy, merged by map ID. |
| `maps.csv.gz` | Gzip-compressed source map data. |
| `keys_imported.csv` | Keys from external sources. |
| `keys_exact.csv` | All keys recovered by the deterministic solver, including imported matches. |
| `keys_predicted.csv` | Model predictions; may be incorrect. |
| `keys_merged.yaml` | Final keys, merged by map ID and date with priority Exact → Imported → Predicted. |

CSV key files use `id,date,key`. ID and date identify a map version; keys are escaped and hex-encoded.

`keys_merged.yaml` is regenerated on each normal run as a list of `id`, `date`, and `key` entries, sorted by numeric ID then date. Dates and keys are quoted strings, preserving leading zeros and the original key encoding. Evaluation (`-evaluate`) leaves all files unchanged.
