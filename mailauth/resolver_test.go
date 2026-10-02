package mailauth

import (
	"context"
	"net"
	"net/netip"
	"strings"
)

// fakeResolver answers from maps; names in temp fail with a temporary error.
type fakeResolver struct {
	txt  map[string][]string
	ip   map[string][]string
	mx   map[string][]string
	temp map[string]bool
}

func (r *fakeResolver) err(name string) error {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if r.temp[name] {
		return &net.DNSError{Err: "server failure", Name: name, IsTemporary: true}
	}
	return &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (r *fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	key := strings.TrimSuffix(strings.ToLower(name), ".")
	if v, ok := r.txt[key]; ok && !r.temp[key] {
		return v, nil
	}
	return nil, r.err(name)
}

func (r *fakeResolver) LookupNetIP(_ context.Context, network, host string) ([]netip.Addr, error) {
	key := strings.TrimSuffix(strings.ToLower(host), ".")
	values, ok := r.ip[key]
	if !ok || r.temp[key] {
		return nil, r.err(host)
	}
	var addrs []netip.Addr
	for _, v := range values {
		addr := netip.MustParseAddr(v)
		if (network == "ip4" && addr.Is4()) || (network == "ip6" && addr.Is6()) || network == "ip" {
			addrs = append(addrs, addr)
		}
	}
	if len(addrs) == 0 {
		return nil, r.err(host)
	}
	return addrs, nil
}

func (r *fakeResolver) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	key := strings.TrimSuffix(strings.ToLower(name), ".")
	hosts, ok := r.mx[key]
	if !ok || r.temp[key] {
		return nil, r.err(name)
	}
	var mxs []*net.MX
	for i, h := range hosts {
		mxs = append(mxs, &net.MX{Host: h + ".", Pref: uint16(10 * (i + 1))})
	}
	return mxs, nil
}
