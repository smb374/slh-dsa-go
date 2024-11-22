package address

import "codeberg.org/smb374/slh-dsa-go/utils"

type AddressType = uint32

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
func SetLayerAddress(adrs Address, laddr uint32) {
	result := utils.ToByte(uint(laddr), 4)
	copy(adrs[0:4], result[0:4])
}

// tree address: 12-byte unsigned integer
func SetTreeAddress(adrs Address, taddr uint) {
	result := utils.ToByte(taddr, 12)
	copy(adrs[4:16], result[0:12])
}

func SetTypeAndClear(adrs Address, Y AddressType) {
	result := utils.ToByte(uint(Y), 4)
	zeroes := [12]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	copy(adrs[16:20], result[0:4])
	copy(adrs[20:], zeroes[:])
}

func SetKeyPairAddress(adrs Address, iaddr uint32) {
	result := utils.ToByte(uint(iaddr), 4)
	copy(adrs[20:24], result[0:4])
}

func SetChainAddress(adrs Address, iaddr uint32) {
	result := utils.ToByte(uint(iaddr), 4)
	copy(adrs[24:28], result[0:4])
}

func SetTreeHeight(adrs Address, iaddr uint32) {
	result := utils.ToByte(uint(iaddr), 4)
	copy(adrs[24:28], result[0:4])
}

func SetHashAddress(adrs Address, iaddr uint32) {
	result := utils.ToByte(uint(iaddr), 4)
	copy(adrs[28:32], result[0:4])
}

func SetTreeIndex(adrs Address, iaddr uint32) {
	result := utils.ToByte(uint(iaddr), 4)
	copy(adrs[28:32], result[0:4])
}

func GetKeyPairAddress(adrs Address) uint32 {
	return uint32(utils.ToInt(adrs[20:24], 4))
}

func GetTreeIndex(adrs Address) uint32 {
	return uint32(utils.ToInt(adrs[24:28], 4))
}
