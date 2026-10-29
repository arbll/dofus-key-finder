| File | Purpose |
| --- | --- |
| `maps.csv` | Source map data (Git LFS). |
| `keys-imported.csv` | Keys from external sources. |
| `keys-exact.csv` | All keys recovered by the deterministic solver, including imported matches. |
| `keys-predicted.csv` | Model predictions; may be incorrect. Currently empty. |

Key files use `id,date,key`. ID and date identify a map version; keys are escaped and hex-encoded.
