package gnark_ptau

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/kzg"
)

// ToSRS converts a SnarkJS PTAU file to a Gnark bn254 KZG SRS.
//
// See https://github.com/iden3/snarkjs/blob/e44656d9e7b451250038211e44c1a7d80dd76b89/src/powersoftau_new.js#L20-L66.
func ToSRS(reader io.Reader) (*kzg.SRS, error) {
	var ptauStr = make([]byte, 4)
	_, err := reader.Read(ptauStr)
	if err != nil {
		return nil, err
	}

	// version
	_, err = readULE32(reader)
	if err != nil {
		return nil, err
	}

	// number of sections
	sections, err := readULE32(reader)
	if err != nil {
		return nil, err
	}
	if sections < 3 {
		return nil, fmt.Errorf("unexpected section count %d, expected at least 3", sections)
	}

	var srs kzg.SRS
	power := uint32(0)
	for i := 0; i < 3; i++ {
		section, err := readULE32(reader)
		if err != nil {
			return nil, err
		}
		if section != uint32(i+1) {
			return nil, fmt.Errorf("unexpected section %d, expected %d", section, i+1)
		}
		length, err := readULE64(reader)
		if err != nil {
			return nil, err
		}
		switch i {
		case 0:
			power, err = readHeader(reader, length)
		case 1:
			err = readG1Array(reader, length, power, &srs)
		case 2:
			err = readG2Array(reader, length, power, &srs)
		}
		if err != nil {
			return nil, err
		}
	}

	return &srs, nil
}

func readHeader(reader io.Reader, length uint64) (uint32, error) {
	numberOfBytes, err := readULE32(reader)
	if err != nil {
		return 0, err
	}
	if numberOfBytes != fr.Bytes {
		return 0, fmt.Errorf("unexpected n8 %d, expected %d", numberOfBytes, fr.Bytes)
	}
	if length != uint64(numberOfBytes)+12 {
		return 0, fmt.Errorf("unexpected length %d, expected %d", length, numberOfBytes+12)
	}
	// prime
	_, err = readElement(reader)
	if err != nil {
		return 0, err
	}
	// power
	power, err := readULE32(reader)
	if err != nil {
		return 0, err
	}
	// ceremonyPower
	_, err = readULE32(reader)
	if err != nil {
		return 0, err
	}
	return power, nil
}

func readG1Array(reader io.Reader, length uint64, power uint32, srs *kzg.SRS) error {
	numPoints := uint64(1<<power)*2 - 1
	if length != numPoints*64 {
		return fmt.Errorf("unexpected length %d, expected %d", length, numPoints*64)
	}
	srs.Pk.G1 = make([]bn254.G1Affine, numPoints)
	var err error
	for i := uint64(0); i < numPoints; i++ {
		srs.Pk.G1[i], err = readG1(reader)
		if err != nil {
			return err
		}
		if !srs.Pk.G1[i].IsOnCurve() {
			return fmt.Errorf("G1 not on curve: \n index: %d g1Affine.X: %s \n g1Affine.Y: %s \n", i, srs.Pk.G1[i].X, srs.Pk.G1[i].Y)
		}
	}
	srs.Vk.G1 = srs.Pk.G1[0]
	return nil
}

func readG2Array(reader io.Reader, length uint64, power uint32, srs *kzg.SRS) error {
	numPoints := uint64(1 << power)
	if length != numPoints*64 {
		return fmt.Errorf("unexpected length %d, expected %d", length, numPoints*64)
	}
	var err error
	for i := 0; i < 2; i++ {
		srs.Vk.G2[i], err = readG2(reader)
		if err != nil {
			return err
		}
		if !srs.Vk.G2[i].IsOnCurve() {
			return fmt.Errorf("tauG2: \n index: %d, g2Affine.X.A0: %s \n g2Affine.X.A1: %s \n g2Affine.Y.A0: %s \n g2Affine.Y.A1 %s \n", i, srs.Vk.G2[i].X.A0, srs.Vk.G2[i].X.A1, srs.Vk.G2[i].Y.A0, srs.Vk.G2[i].Y.A1)
		}
	}
	return nil
}

func readG1(reader io.Reader) (bn254.G1Affine, error) {
	var g1 bn254.G1Affine
	var err error
	g1.X, err = readElement(reader)
	if err != nil {
		return bn254.G1Affine{}, err
	}
	g1.Y, err = readElement(reader)
	if err != nil {
		return bn254.G1Affine{}, err
	}
	return g1, nil
}

func readG2(reader io.Reader) (bn254.G2Affine, error) {
	var g2 bn254.G2Affine
	var err error
	g2.X.A0, err = readElement(reader)
	if err != nil {
		return bn254.G2Affine{}, err
	}
	g2.X.A1, err = readElement(reader)
	if err != nil {
		return bn254.G2Affine{}, err
	}
	g2.Y.A0, err = readElement(reader)
	if err != nil {
		return bn254.G2Affine{}, err
	}
	g2.Y.A1, err = readElement(reader)
	if err != nil {
		return bn254.G2Affine{}, err
	}
	return g2, nil
}

func readULE32(reader io.Reader) (uint32, error) {
	var buffer = make([]byte, 4)
	_, err := reader.Read(buffer)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(buffer), nil
}

func readULE64(reader io.Reader) (uint64, error) {
	var buffer = make([]byte, 8)
	_, err := reader.Read(buffer)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(buffer), nil
}

func readElement(reader io.Reader) (fp.Element, error) {
	var buffer = make([]byte, fr.Bytes)
	_, err := reader.Read(buffer)
	if err != nil {
		return fp.Element{}, err
	}
	reverseSlice(buffer)
	return bytesToElement(buffer), nil
}

func reverseSlice(slice []byte) []byte {
	for i := 0; i < len(slice)/2; i++ {
		j := len(slice) - i - 1
		slice[i], slice[j] = slice[j], slice[i]
	}
	return slice
}

func bytesToElement(b []byte) fp.Element {
	var z fp.Element
	reverseSlice(b)
	if len(b) < 32 {
		b = append(b, make([]byte, 32-len(b))...)
	}
	z[0] = binary.LittleEndian.Uint64(b[0:8])
	z[1] = binary.LittleEndian.Uint64(b[8:16])
	z[2] = binary.LittleEndian.Uint64(b[16:24])
	z[3] = binary.LittleEndian.Uint64(b[24:32])
	return z
}
