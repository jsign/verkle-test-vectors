package main

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"testing"

	"github.com/crate-crypto/go-ipa/bandersnatch/fp"
	"github.com/crate-crypto/go-ipa/bandersnatch/fr"
	"github.com/crate-crypto/go-ipa/banderwagon"
	"github.com/crate-crypto/go-ipa/ipa"
	"github.com/stretchr/testify/require"
)

func Test001(t *testing.T) {
	t.Parallel()

	type testType = struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		TestData    struct {
			Scalars              []string `json:"scalars"`
			SerializedCommitment string   `json:"serializedCommitment"`
		} `json:"testData"`
	}
	var data testType
	readTestFile(t, "../../001_vector_commitment.json", &data)

	scalars := make([]fr.Element, 256)
	for i := 0; i < 256; i++ {
		scalars[i].SetString(data.TestData.Scalars[i])
	}
	config, err := ipa.NewIPASettings()
	require.NoError(t, err)

	comm := config.Commit(scalars).Bytes()
	gotComm := hex.EncodeToString(comm[:])

	require.Equal(t, data.TestData.SerializedCommitment[2:], gotComm)
}

func Test002(t *testing.T) {
	t.Parallel()

	type testType = struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		TestData    struct {
			SerializedPoint string `json:"serializedPoint"`
			FieldElement    string `json:"fieldElement"`
		} `json:"testData"`
	}
	var data testType
	readTestFile(t, "../../002_map_to_field_element.json", &data)

	var point banderwagon.Element
	pointBytes, err := hex.DecodeString(data.TestData.SerializedPoint[2:])
	require.NoError(t, err)
	err = point.SetBytes(pointBytes)
	require.NoError(t, err)

	var got fr.Element
	point.MapToScalarField(&got)

	require.Equal(t, data.TestData.FieldElement, got.String())
}

func Test003(t *testing.T) {
	t.Parallel()

	type testType = struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		TestData    struct {
			SerializeXCoordinate    string `json:"serializedXCoordinate"`
			SerializeYCoordinate    string `json:"serializedYCoordinate"`
			ExpectedSerializedPoint string `json:"expectedSerializedPoint"`
		} `json:"testData"`
	}
	var data testType
	readTestFile(t, "../../003_serialize_lexicographically_highest.json", &data)

	xCoordBytes, err := hex.DecodeString(data.TestData.SerializeXCoordinate[2:])
	require.NoError(t, err)
	yCoordBytes, err := hex.DecodeString(data.TestData.SerializeYCoordinate[2:])
	require.NoError(t, err)
	var y fp.Element
	y.SetBytes(yCoordBytes)
	require.True(t, y.LexicographicallyLargest()) // Shouldn't be needed -- double-check test assumption.

	var point banderwagon.Element
	err = point.SetBytesUncompressed(append(xCoordBytes, yCoordBytes...), false) // Use false just to be sure.
	require.NoError(t, err)

	gotSerializedPoint := point.Bytes()
	expSerializedPoint, err := hex.DecodeString(data.TestData.ExpectedSerializedPoint[2:])
	require.NoError(t, err)
	require.Equal(t, gotSerializedPoint[:], expSerializedPoint)
}

func Test004(t *testing.T) {
	t.Parallel()

	type testType = struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		TestData    struct {
			SerializeXCoordinate    string `json:"serializedXCoordinate"`
			SerializeYCoordinate    string `json:"serializedYCoordinate"`
			ExpectedSerializedPoint string `json:"expectedSerializedPoint"`
		} `json:"testData"`
	}
	var data testType
	readTestFile(t, "../../004_serialize_lexicographically_lowest.json", &data)

	xCoordBytes, err := hex.DecodeString(data.TestData.SerializeXCoordinate[2:])
	require.NoError(t, err)
	yCoordBytes, err := hex.DecodeString(data.TestData.SerializeYCoordinate[2:])
	require.NoError(t, err)
	var y fp.Element
	y.SetBytes(yCoordBytes)
	require.False(t, y.LexicographicallyLargest()) // Double-check test assumption.

	var point banderwagon.Element
	err = point.SetBytesUncompressed(append(xCoordBytes, yCoordBytes...), false) // Use false just to be sure.
	require.NoError(t, err)

	gotSerializedPoint := point.Bytes()
	expSerializedPoint, err := hex.DecodeString(data.TestData.ExpectedSerializedPoint[2:])
	require.NoError(t, err)
	require.Equal(t, gotSerializedPoint[:], expSerializedPoint)
}

func Test005(t *testing.T) {
	t.Parallel()

	type testType = struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		TestData    struct {
			SerializedPoint string `json:"serializedPoint"`
		} `json:"testData"`
	}
	var data testType
	readTestFile(t, "../../005_deserialize_point_not_in_curve.json", &data)

	serializedBytes, err := hex.DecodeString(data.TestData.SerializedPoint[2:])
	require.NoError(t, err)

	var point banderwagon.Element
	// TODO: consider go-ipa returning wrapped-sentinel errors to be more specific
	// about the error type.
	if err := point.SetBytesUncompressed(serializedBytes, false); err == nil {
		t.Fatalf("expected error, got nil")
	}
}

func readTestFile(t *testing.T, testFilePath string, out interface{}) {
	t.Helper()

	f, err := os.Open(testFilePath)
	require.NoError(t, err)
	defer f.Close()

	content, err := io.ReadAll(f)
	require.NoError(t, err)

	err = json.Unmarshal(content, out)
	require.NoError(t, err)
}
