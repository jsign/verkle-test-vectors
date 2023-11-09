package geth

import (
	"encoding/json"
	"io"
	"math/big"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/trie/utils"
	"github.com/gballet/go-verkle"
	"github.com/stretchr/testify/require"
)

func TestTree001(t *testing.T) {
	type testType = struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		TestData    struct {
			EOAAddress       string `json:"eoaAddress"`
			Nonce            uint64 `json:"nonce"`
			Balance          uint64 `json:"balance"`
			ExpectedRootHash string `json:"expectedRootHash"`
		} `json:"testData"`
	}
	var data testType
	readTestFile(t, "../../tree/001_eoa_insert.json", &data)

	tree := trie.NewVerkleTrie(verkle.New(), nil, utils.NewPointCache(), true)

	addr := common.HexToAddress(data.TestData.EOAAddress)
	stateAccount := types.StateAccount{
		Nonce:    data.TestData.Nonce,
		Balance:  new(big.Int).SetUint64(data.TestData.Balance),
		CodeHash: types.EmptyCodeHash[:],
	}
	err := tree.UpdateAccount(addr, &stateAccount)
	require.NoError(t, err)

	require.Equal(t, data.TestData.ExpectedRootHash, tree.Hash().Hex())
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
