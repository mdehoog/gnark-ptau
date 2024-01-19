# gnark-ptau

Golang library + utility for converting from SnarkJS ptau files to a gnark `kzg.SRS`.

### Usage

1. Generate or download a .ptau file using the [SnarkJS instructions](https://github.com/iden3/snarkjs/blob/master/README.md#7-prepare-phase-2).
2. Install `ptau2gnark`:
    ```bash
    go install github.com/mdehoog/gnark-ptau/cmd/ptau2gnark@latest
    ```
3. Convert the .ptau file to a gnark `kzg.SRS`:
    ```bash
    ptau2gnark <path to .ptau file> <path to output .srs file>
    ```
4. Use the `kzg.SRS` in your gnark circuit:
    ```golang
	var k kzg.SRS
    srs, _ := os.Open("<path to output .srs file>")
	_, err = k.ReadFrom(srs)
    ```
