package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	multiproof "github.com/crate-crypto/go-ipa"
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
			SerializeXCoordinate string `json:"serializedXCoordinate"`
			SerializeYCoordinate string `json:"serializedYCoordinate"`
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
	// Consider go-ipa returning wrapped-sentinel errors to be more specific.
	if err == nil || !strings.Contains(err.Error(), "Y coordinate doesn't correspond to X") {
		t.Fatalf("expected concrete error %s", err)
	}
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

func Test006(t *testing.T) {
	t.Parallel()

	type testType = struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		TestData    struct {
			SerializedPoint string `json:"serializedPoint"`
		} `json:"testData"`
	}
	var data testType
	readTestFile(t, "../../006_deserialize_point_not_in_subgroup.json", &data)

	serializedBytes, err := hex.DecodeString(data.TestData.SerializedPoint[2:])
	require.NoError(t, err)

	var point banderwagon.Element
	if err := point.SetBytesUncompressed(serializedBytes, false); err == nil {
		t.Fatalf("expected error, got nil")
	}
}

func Test007(t *testing.T) {
	t.Parallel()

	type testType = struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		TestData    struct {
			SerializedPoint string `json:"serializedPoint"`
		} `json:"testData"`
	}
	var data testType
	readTestFile(t, "../../007_deserialize_point_x_bigger_than_field.json", &data)

	serializedBytes, err := hex.DecodeString(data.TestData.SerializedPoint[2:])
	require.NoError(t, err)

	var point banderwagon.Element
	err = point.SetBytes(serializedBytes)
	// Consider go-ipa returning wrapped-sentinel errors to be more specific.
	if err == nil || !strings.Contains(err.Error(), "invalid compressed point") {
		t.Fatalf("expected concrete error")
	}
}

func Test008(t *testing.T) {
	t.Parallel()

	type testType = struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		TestData    struct {
			SerializedPoints []string `json:"serializedPoint"`
		} `json:"testData"`
	}
	var data testType
	readTestFile(t, "../../008_deserialize_point_x_wrong_length.json", &data)

	for _, serializedPoint := range data.TestData.SerializedPoints {
		serializedBytes, err := hex.DecodeString(serializedPoint[2:])
		require.NoError(t, err)

		var point banderwagon.Element
		err = point.SetBytes(serializedBytes)
		// Consider go-ipa returning wrapped-sentinel errors to be more specific.
		if err == nil || !strings.Contains(err.Error(), "invalid compressed point") {
			t.Fatalf("expected concrete error")
		}
	}
}

func Test009(t *testing.T) {
	t.Parallel()

	type testType = struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		TestData    struct {
			SerializedProof string `json:"serializedProof"`
		} `json:"testData"`
	}
	var data testType
	readTestFile(t, "../../009_deserialize_proof_invalid_final_scalar.json", &data)

	proofBytes, err := hex.DecodeString(data.TestData.SerializedProof[2:])
	require.NoError(t, err)

	var proof multiproof.MultiProof
	// Consider go-ipa returning wrapped-sentinel errors to be more specific.
	if err := proof.Read(bytes.NewReader(proofBytes)); err == nil || !strings.Contains(err.Error(), "failed to read A_scalar") {
		t.Fatalf("expected concrete error")
	}
}

func Test010(t *testing.T) {
	t.Parallel()

	type testType = struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		TestData    struct {
			SerializedProofs []string `json:"serializedProofs"`
		} `json:"testData"`
	}
	var data testType
	readTestFile(t, "../../010_deserialize_proof_wrong_length.json", &data)

	for _, serializedProof := range data.TestData.SerializedProofs {
		proofBytes, err := hex.DecodeString(serializedProof[2:])
		require.NoError(t, err)

		var proof multiproof.MultiProof
		// Consider go-ipa returning wrapped-sentinel errors to be more specific.
		if err := proof.Read(bytes.NewReader(proofBytes)); err == nil || !strings.Contains(err.Error(), "EOF") {
			t.Fatalf("expected concrete error %s", err)
		}
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
