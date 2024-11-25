package address

import "github.com/smb374/slh-dsa-go/utils"

type AddressType = int

const (
	WOTS_HASH  AddressType = 0
	WOTS_PK    AddressType = 1
	TREE       AddressType = 2
	FORS_TREE  AddressType = 3
	FORS_ROOTS AddressType = 4
	WOTS_PRF   AddressType = 5
	FORS_PRF   AddressType = 6
)

type Address = [32]byte

// Member functions
func SetLayerAddress(adrs *Address, laddr int) {
	result := utils.ToByte(laddr, 4)
	copy(adrs[:4], result[:])
}

// tree address: 12-byte unsigned integer
func SetTreeAddress(adrs *Address, taddr int) {
	result := utils.ToByte(taddr, 12)
	copy(adrs[4:16], result[:])
}

func SetTypeAndClear(adrs *Address, Y AddressType) {
	result := utils.ToByte(Y, 4)
	zeroes := utils.ToByte(0, 12)
	copy(adrs[16:20], result[:])
	copy(adrs[20:], zeroes[:])
}

func SetKeyPairAddress(adrs *Address, iaddr int) {
	result := utils.ToByte(iaddr, 4)
	copy(adrs[20:24], result[:])
}

func SetChainAddress(adrs *Address, iaddr int) {
	result := utils.ToByte(iaddr, 4)
	copy(adrs[24:28], result[:])
}

func SetTreeHeight(adrs *Address, iaddr int) {
	result := utils.ToByte(iaddr, 4)
	copy(adrs[24:28], result[:])
}

func SetHashAddress(adrs *Address, iaddr int) {
	result := utils.ToByte(iaddr, 4)
	copy(adrs[28:], result[:])
}

func SetTreeIndex(adrs *Address, iaddr int) {
	result := utils.ToByte(iaddr, 4)
	copy(adrs[28:], result[:])
}

func GetKeyPairAddress(adrs *Address) int {
	return utils.ToInt(adrs[20:24], 4)
}

func GetTreeIndex(adrs *Address) int {
	return utils.ToInt(adrs[28:], 4)
}
