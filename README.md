<div align="center">

# Dofus Key Finder

[![The same Dofus map rendered with an incorrect key on the left and a correct key on the right](docs/assets/map-key-comparison.png)](https://arthur.bell.al/blog/breaking-dofus-1.29.1-maps-encryption/)

<sub>Incorrect key → correct key · Map artwork © Ankama Games</sub>

Recover decryption keys for Dofus 1.29 maps from encrypted map data.

[How the attack works](https://arthur.bell.al/blog/breaking-dofus-1.29.1-maps-encryption/) · [Data files](data/README.md) · [Usage](#usage)

</div>

## Progress

<sub><em><a href="https://github.com/arbll/dofus-key-finder/releases/latest/download/keys_merged.yaml">Download the latest keys</a></em></sub>

The bundled data contains **9,811 map IDs** across **21,917 versions**: **9,007 plaintext** and **12,910 encrypted**.

| Encrypted map versions | Count | Share |
| :--- | ---: | ---: |
| Exact key | 3,258 | 25.24% |
| Imported key only | 6,210 | 48.10% |
| Prediction only | 3,442 | 26.66% |
| **Total** | **12,910** | **100%** |

- **Exact key:** the solver found only one possible key under its map-format rules.
- **Imported key only:** a key from an external source that the solver has not confirmed.
- **Prediction only:** a key guessed using statistics from known keys. It may be wrong.

## Usage

### Install

Download a binary for your platform from [GitHub Releases](https://github.com/arbll/dofus-key-finder/releases), or install with **[Go 1.27.3+](https://go.dev/dl/)**:

```sh
go install github.com/arbll/dofus-key-finder/cmd/dofus-key-finder@latest
```

Add Go's install directory (`go env GOBIN`, or `$(go env GOPATH)/bin` if unset) to your `PATH`.

### Run

Get the bundled data and run from the repository root:

```sh
git clone https://github.com/arbll/dofus-key-finder.git
cd dofus-key-finder
dofus-key-finder
```

Reads the bundled maps and imported keys, updates `data/keys_exact.csv` and `data/keys_predicted.csv`, writes the final result to `data/keys_merged.yaml`, and prints a coverage summary. The merged file contains one key per map ID and date, with priority **Exact → Imported → Predicted**. Use `-merged-keys-file` to change its output path.

| Task | Command |
| :--- | :--- |
| Evaluate predictions without updating files | `dofus-key-finder -evaluate` |
| Show recovery details | `dofus-key-finder -verbose` |
| Show options and custom file paths | `dofus-key-finder -h` |
| Run tests from the repository root | `go test ./...` |
