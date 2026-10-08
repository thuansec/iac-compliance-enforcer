package terraform

import (
	"errors"
	"fmt"
	"math/big"
	"net/netip"

	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
)

// Terraform's network functions, written from its documentation with net/netip and math/big.
// Prefixes are parsed strictly (no leading zeros, no zones). An IPv4-mapped IPv6 address, in a
// prefix or in a result, is refused: Terraform prints one as IPv4 text with its own mask rules
// (cidrsubnet("::/80", 16, 65535) is "0.0.0.0/0" there), which iace does not reproduce, so such
// a value is unknown rather than different. Host bits in a prefix are dropped, as Terraform
// does. Error messages never quote the arguments, which may be sensitive or huge.

// parsePrefix parses a CIDR prefix argument and returns it with host bits dropped, and its
// network address as an integer.
func parsePrefix(s string) (netip.Prefix, *big.Int, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, nil, function.NewArgErrorf(0, "invalid CIDR prefix")
	}
	if p.Addr().Is4In6() || p.Addr().Zone() != "" {
		return netip.Prefix{}, nil, function.NewArgErrorf(0, "unsupported CIDR prefix: IPv4-mapped IPv6 addresses and zones are not supported")
	}
	p = p.Masked()
	return p, new(big.Int).SetBytes(p.Addr().AsSlice()), nil
}

// wholeNumber converts a number argument to an integer, which it must be.
func wholeNumber(arg int, v cty.Value) (*big.Int, error) {
	f := v.AsBigFloat()
	if !f.IsInt() {
		return nil, function.NewArgErrorf(arg, "must be a whole number")
	}
	n, _ := f.Int(nil)
	return n, nil
}

// maxNewbits is Terraform's limit on how far cidrsubnet extends a prefix.
const maxNewbits = 32

// addrFromInt returns the address of bits length whose value is n.
func addrFromInt(n *big.Int, bits int) netip.Addr {
	b := make([]byte, bits/8)
	n.FillBytes(b)
	addr, _ := netip.AddrFromSlice(b)
	return addr
}

var cidrSubnetFunc = function.New(&function.Spec{
	Description: "Calculates a subnet address within a given IP network address prefix.",
	Params: []function.Parameter{
		{Name: "prefix", Type: cty.String},
		{Name: "newbits", Type: cty.Number},
		{Name: "netnum", Type: cty.Number},
	},
	Type: function.StaticReturnType(cty.String),
	Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
		p, base, err := parsePrefix(args[0].AsString())
		if err != nil {
			return cty.NilVal, err
		}
		newbits, err := wholeNumber(1, args[1])
		if err != nil {
			return cty.NilVal, err
		}
		netnum, err := wholeNumber(2, args[2])
		if err != nil {
			return cty.NilVal, err
		}
		bits := p.Addr().BitLen()
		free := bits - p.Bits()
		if newbits.Sign() < 0 || newbits.Cmp(big.NewInt(int64(min(free, maxNewbits)))) > 0 {
			return cty.NilVal, function.NewArgErrorf(1, "cannot extend a prefix of %d by that many bits (at most %d, and %d left)", p.Bits(), maxNewbits, free)
		}
		nb := int(newbits.Int64())
		if netnum.Sign() < 0 || netnum.BitLen() > nb {
			return cty.NilVal, function.NewArgErrorf(2, "prefix extension of %d does not accommodate the subnet number", nb)
		}
		addr := addrFromInt(new(big.Int).Or(base, new(big.Int).Lsh(netnum, uint(free-nb))), bits)
		if addr.Is4In6() {
			return cty.NilVal, function.NewArgErrorf(2, "the subnet is an IPv4-mapped IPv6 prefix, which is not supported")
		}
		return cty.StringVal(netip.PrefixFrom(addr, p.Bits()+nb).String()), nil
	},
})

var cidrHostFunc = function.New(&function.Spec{
	Description: "Calculates a full host IP address within a given IP network address prefix.",
	Params: []function.Parameter{
		{Name: "prefix", Type: cty.String},
		{Name: "hostnum", Type: cty.Number},
	},
	Type: function.StaticReturnType(cty.String),
	Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
		p, base, err := parsePrefix(args[0].AsString())
		if err != nil {
			return cty.NilVal, err
		}
		hostnum, err := wholeNumber(1, args[1])
		if err != nil {
			return cty.NilVal, err
		}
		bits := p.Addr().BitLen()
		size := new(big.Int).Lsh(big.NewInt(1), uint(bits-p.Bits()))
		n := new(big.Int).Set(hostnum)
		if n.Sign() < 0 {
			n.Add(n, size) // a negative host number counts back from the end
		}
		if n.Sign() < 0 || n.Cmp(size) >= 0 {
			return cty.NilVal, function.NewArgErrorf(1, "prefix of %d does not accommodate the host number", p.Bits())
		}
		addr := addrFromInt(new(big.Int).Or(base, n), bits)
		if addr.Is4In6() {
			return cty.NilVal, function.NewArgErrorf(1, "the host is an IPv4-mapped IPv6 address, which is not supported")
		}
		return cty.StringVal(addr.String()), nil
	},
})

var cidrNetmaskFunc = function.New(&function.Spec{
	Description: "Converts an IPv4 address prefix given in CIDR notation into a subnet mask address.",
	Params:      []function.Parameter{{Name: "prefix", Type: cty.String}},
	Type:        function.StaticReturnType(cty.String),
	Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
		p, _, err := parsePrefix(args[0].AsString())
		if err != nil {
			return cty.NilVal, err
		}
		if !p.Addr().Is4() {
			return cty.NilVal, function.NewArgError(0, errors.New("only IPv4 networks are supported"))
		}
		mask := ^uint32(0) << (32 - p.Bits()) // a shift by 32 gives 0
		return cty.StringVal(fmt.Sprintf("%d.%d.%d.%d", mask>>24, mask>>16&0xff, mask>>8&0xff, mask&0xff)), nil
	},
})
