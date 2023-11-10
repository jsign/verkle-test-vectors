package main

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"testing"

	"github.com/crate-crypto/go-ipa/bandersnatch/fr"
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

	require.Equal(t, data.TestData.SerializedCommitment, gotComm)
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
