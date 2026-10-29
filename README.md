<div align="center">

# Dofus Key Finder

[![The same Dofus map rendered with an incorrect key on the left and a correct key on the right](docs/assets/map-key-comparison.png)](https://arthur.bell.al/blog/breaking-dofus-1.29.1-maps-encryption/)

<sub>Incorrect key → correct key · Map artwork © Ankama Games</sub>

Recover decryption keys for Dofus 1.29 maps from encrypted map data.

[How the attack works](https://arthur.bell.al/blog/breaking-dofus-1.29.1-maps-encryption/) · [Data files](data/README.md) · [Usage](#usage)

</div>

## Coverage

The bundled data contains **9,811 map IDs** across **21,917 versions**: **9,007 plaintext** and **12,910 encrypted**.

| Encrypted map versions | Count | Share |
| :--- | ---: | ---: |
| Exact key | 3,258 | 25.24% |
| Imported key only | 6,210 | 48.10% |
| Prediction only | 3,442 | 26.66% |
| **Total** | **12,910** | **100%** |

**73.34% have an imported or exact key.** Exact keys are unique under the solver's constraints; imported keys are unverified. Predictions may be wrong and are excluded from known-key coverage.

## Usage

Requires **Go 1.22+**. Run from the repository root:

```sh
go run ./cmd/dofus-key-finder
```

The solver applies map-format constraints, then predicts unresolved bytes using statistics learned from known keys. It updates `data/keys_exact.csv` and `data/keys_predicted.csv` and prints a coverage summary.

```sh
# Evaluate on held-out known keys without updating files
go run ./cmd/dofus-key-finder -evaluate

# Run tests
go test ./...
```

Use `-verbose` for recovery details or `-h` for all options, including custom file paths.
