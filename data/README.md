| File | Purpose |
| --- | --- |
| `maps_metadata.csv` | Incomplete world coordinates and area hierarchy, merged by map ID. |
| `maps.csv.gz` | Gzip-compressed source map data. |
| `keys_imported.csv` | Keys from external sources. |
| `keys_exact.csv` | All keys recovered by the deterministic solver, including imported matches. |
| `keys_predicted.csv` | Model predictions; may be incorrect. |

Key files use `id,date,key`. ID and date identify a map version; keys are escaped and hex-encoded.
