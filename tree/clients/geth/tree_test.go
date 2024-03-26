package geth

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/trie/utils"
	"github.com/ethereum/go-verkle"
	"github.com/stretchr/testify/require"
)

func TestTree001(t *testing.T) {
	t.Parallel()

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
	readTestFile(t, "../../001_eoa_insert.json", &data)

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

func TestTree002(t *testing.T) {
	t.Parallel()

	type testType = struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		TestData    struct {
			SCAddress        string `json:"scAddress"`
			Nonce            uint64 `json:"nonce"`
			Balance          uint64 `json:"balance"`
			HexCode          string `json:"hexCode"`
			ExpectedRootHash string `json:"expectedRootHash"`
		} `json:"testData"`
	}
	var data testType
	readTestFile(t, "../../002_sc_insert.json", &data)

	tree := trie.NewVerkleTrie(verkle.New(), nil, utils.NewPointCache(), true)

	addr := common.HexToAddress(data.TestData.SCAddress)
	code, err := hex.DecodeString(data.TestData.HexCode[2:])
	require.NoError(t, err)
	codeHash := crypto.Keccak256Hash(code)
	stateAccount := types.StateAccount{
		Nonce:    data.TestData.Nonce,
		Balance:  new(big.Int).SetUint64(data.TestData.Balance),
		CodeHash: codeHash.Bytes(),
	}
	err = tree.UpdateAccount(addr, &stateAccount)
	require.NoError(t, err)
	err = tree.UpdateContractCode(addr, codeHash, code)
	require.NoError(t, err)

	require.Equal(t, data.TestData.ExpectedRootHash, tree.Hash().Hex())
}

func TestTree003(t *testing.T) {
	t.Parallel()

	type testType = struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		TestData    struct {
			Mutations []struct {
				Key   string `json:"key"`
				Value string `json:"value"`
			} `json:"mutations"`
			ExpectedRootHash string `json:"expectedRootHash"`
		} `json:"testData"`
	}
	var data testType
	readTestFile(t, "../../003_tree_mutation.json", &data)

	rawTree := verkle.New()
	for i := range data.TestData.Mutations {
		key, err := hex.DecodeString(data.TestData.Mutations[i].Key[2:])
		require.NoError(t, err)
		val, err := hex.DecodeString(data.TestData.Mutations[i].Value[2:])
		require.NoError(t, err)
		err = rawTree.Insert(key, val, nil)
		require.NoError(t, err)
	}

	got := rawTree.Commit().Bytes()
	require.Equal(t, data.TestData.ExpectedRootHash[2:], hex.EncodeToString(got[:]))
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
