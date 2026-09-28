// Package discover walks a FortiGate and reports what can actually be
// monitored, so interfaces are chosen from live device data rather than
// hand-typed into a configuration file.
package discover

import (
	"fmt"
	"sort"
	"strings"

	"fgwan/internal/ber"
	"fgwan/internal/snmp"
)

// IF-MIB and system columns used for inventory.
var (
	oidSysDescr    = ber.MustParseOIDString("1.3.6.1.2.1.1.1.0")
	oidSysObjectID = ber.MustParseOIDString("1.3.6.1.2.1.1.2.0")
	oidSysUpTime   = ber.MustParseOIDString("1.3.6.1.2.1.1.3.0")
	oidSysName     = ber.MustParseOIDString("1.3.6.1.2.1.1.5.0")

	oidIfName      = ber.MustParseOIDString("1.3.6.1.2.1.31.1.1.1.1")
	oidIfAlias     = ber.MustParseOIDString("1.3.6.1.2.1.31.1.1.1.18")
	oidIfHighSpeed = ber.MustParseOIDString("1.3.6.1.2.1.31.1.1.1.15")
	oidIfHCIn      = ber.MustParseOIDString("1.3.6.1.2.1.31.1.1.1.6")
	oidIfType      = ber.MustParseOIDString("1.3.6.1.2.1.2.2.1.3")
	oidIfOper      = ber.MustParseOIDString("1.3.6.1.2.1.2.2.1.8")
	oidIfDescr     = ber.MustParseOIDString("1.3.6.1.2.1.2.2.1.2")
)

// Identity is the device's self-description.
type Identity struct {
	SysName     string `json:"sys_name"`
	SysDescr    string `json:"sys_descr"`
	SysObjectID string `json:"sys_object_id"`
	UptimeTicks uint64 `json:"uptime_ticks"`
	EngineID    string `json:"engine_id"`
}

// Interface is one row of the IF-MIB inventory.
type Interface struct {
	Index      int    `json:"if_index"`
	Name       string `json:"name"`
	Descr      string `json:"descr"`
	Alias      string `json:"alias"`
	Type       int    `json:"if_type"`
	TypeName   string `json:"type_name"`
	OperStatus int    `json:"oper_status"`
	Up         bool   `json:"up"`
	SpeedMbps  int    `json:"speed_mbps"`
	HasHC      bool   `json:"has_hc_counters"`
	Suggested  bool   `json:"suggested"`
	Reason     string `json:"reason"`
}

// Tunnel is one row of the Fortinet IPsec phase-2 table.
type Tunnel struct {
	Index  int    `json:"index"`
	Name   string `json:"name"`
	Status int    `json:"status"`
	Up     bool   `json:"up"`
	In     uint64 `json:"in_octets"`
	Out    uint64 `json:"out_octets"`
}

// VPNColumns is the detected layout of fgVpnTunEntTable.
type VPNColumns struct {
	BaseOID   string `json:"base_oid"`
	Name      uint32 `json:"col_phase2_name"`
	In        uint32 `json:"col_in_octets"`
	Out       uint32 `json:"col_out_octets"`
	Status    uint32 `json:"col_status"`
	UpValue   int64  `json:"status_up_value"`
	Confident bool   `json:"confident"`
	Notes     string `json:"notes"`
	RowCount  int    `json:"row_count"`
}

// Result is the full inventory returned to the setup UI.
type Result struct {
	Identity   Identity    `json:"identity"`
	Interfaces []Interface `json:"interfaces"`
	Tunnels    []Tunnel    `json:"tunnels"`
	VPN        VPNColumns  `json:"vpn_columns"`
	Warnings   []string    `json:"warnings"`
}

// ifTypeName maps the IANAifType values seen on a FortiGate.
func ifTypeName(t int) string {
	switch t {
	case 6:
		return "ethernet"
	case 53:
		return "propVirtual"
	case 131:
		return "tunnel"
	case 135:
		return "l2vlan"
	case 136:
		return "l3ipvlan"
	case 150:
		return "mplsTunnel"
	case 161:
		return "lag"
	case 24:
		return "loopback"
	case 1:
		return "other"
	}
	return fmt.Sprintf("type%d", t)
}

// Probe reads the device identity. It is the cheapest way to prove that the
// SNMPv3 credentials and security parameters are correct.
func Probe(cl *snmp.Client) (Identity, error) {
	vbs, err := cl.Get([][]uint32{oidSysName, oidSysDescr, oidSysObjectID, oidSysUpTime})
	if err != nil {
		return Identity{}, err
	}
	id := Identity{EngineID: fmt.Sprintf("%x", cl.EngineID())}
	if len(vbs) >= 4 {
		id.SysName = vbs[0].Str()
		id.SysDescr = vbs[1].Str()
		if vbs[2].Exists() {
			id.SysObjectID = ber.String(ber.ParseOID(vbs[2].Raw))
		}
		id.UptimeTicks = vbs[3].Uint()
	}
	return id, nil
}

// Interfaces walks the IF-MIB and returns every interface, annotated with
// whether it is a sensible monitoring candidate.
func Interfaces(cl *snmp.Client) ([]Interface, []string, error) {
	var warnings []string

	names, err := cl.Walk(oidIfName)
	if err != nil {
		return nil, nil, fmt.Errorf("walk ifName: %w", err)
	}
	if len(names) == 0 {
		warnings = append(warnings, "ifName returned no rows; falling back to ifDescr")
		if names, err = cl.Walk(oidIfDescr); err != nil {
			return nil, warnings, fmt.Errorf("walk ifDescr: %w", err)
		}
	}

	byIdx := map[int]*Interface{}
	for _, vb := range names {
		i := last(vb.OID)
		byIdx[i] = &Interface{Index: i, Name: vb.Str()}
	}

	collect := func(root []uint32, apply func(*Interface, snmp.VarBind)) {
		rows, err := cl.Walk(root)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("walk %s: %v", ber.String(root), err))
			return
		}
		for _, vb := range rows {
			if f, ok := byIdx[last(vb.OID)]; ok && vb.Exists() {
				apply(f, vb)
			}
		}
	}

	collect(oidIfDescr, func(f *Interface, vb snmp.VarBind) { f.Descr = vb.Str() })
	collect(oidIfAlias, func(f *Interface, vb snmp.VarBind) { f.Alias = vb.Str() })
	collect(oidIfHighSpeed, func(f *Interface, vb snmp.VarBind) { f.SpeedMbps = int(vb.Uint()) })
	collect(oidIfType, func(f *Interface, vb snmp.VarBind) {
		f.Type = int(vb.Int())
		f.TypeName = ifTypeName(f.Type)
	})
	collect(oidIfOper, func(f *Interface, vb snmp.VarBind) {
		f.OperStatus = int(vb.Int())
		f.Up = f.OperStatus == 1
	})
	// Presence of a 64-bit counter decides whether this interface can be
	// measured accurately; tunnel interfaces usually report nothing here.
	collect(oidIfHCIn, func(f *Interface, vb snmp.VarBind) { f.HasHC = true })

	out := make([]Interface, 0, len(byIdx))
	for _, f := range byIdx {
		annotate(f)
		out = append(out, *f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Index < out[j].Index })
	return out, warnings, nil
}

// annotate marks interfaces worth monitoring and explains the verdict.
func annotate(f *Interface) {
	n := strings.ToLower(f.Name)
	switch {
	case !f.HasHC:
		f.Reason = "no 64-bit counters; use the IPsec table instead"
	case f.Type == 24 || strings.HasPrefix(n, "lo"):
		f.Reason = "loopback"
	case strings.HasPrefix(n, "ssl.") || strings.HasPrefix(n, "fortilink") ||
		strings.HasPrefix(n, "npu") || strings.HasPrefix(n, "vsys") ||
		strings.HasPrefix(n, "modem") || n == "any":
		f.Reason = "system interface"
	case !f.Up:
		f.Suggested = false
		f.Reason = "operationally down"
	case f.Type == 6 || f.Type == 161:
		f.Suggested = true
		f.Reason = "physical or aggregate with 64-bit counters"
	default:
		f.Reason = ifTypeName(f.Type)
	}
}

// DetectVPN walks the Fortinet tunnel table and works out which columns carry
// the phase-2 name, the octet counters and the tunnel status. Column numbers
// differ between FortiOS branches, so they are inferred from the data rather
// than assumed, and the caller can override the result.
func DetectVPN(cl *snmp.Client, baseOID string) (VPNColumns, []Tunnel, error) {
	base, err := ber.ParseOIDString(baseOID)
	if err != nil {
		return VPNColumns{}, nil, err
	}
	rows, err := cl.Walk(base)
	if err != nil && len(rows) == 0 {
		return VPNColumns{BaseOID: baseOID}, nil, fmt.Errorf("walk %s: %w", baseOID, err)
	}

	// Group varbinds by column number: base.<column>.<rowIndex>
	type cell struct {
		row int
		vb  snmp.VarBind
	}
	cols := map[uint32][]cell{}
	for _, vb := range rows {
		if len(vb.OID) < len(base)+2 {
			continue
		}
		col := vb.OID[len(base)]
		cols[col] = append(cols[col], cell{row: last(vb.OID), vb: vb})
	}

	out := VPNColumns{BaseOID: baseOID, UpValue: 2}
	if len(cols) == 0 {
		out.Notes = "tunnel table is empty: no IPsec phase-2 selectors, or the base OID is wrong for this FortiOS build"
		return out, nil, nil
	}

	var counterCols []uint32
	for col, cells := range cols {
		strCount, uniq := 0, map[string]bool{}
		counterCount, statusLike := 0, 0
		for _, c := range cells {
			switch c.vb.Tag {
			case ber.TagOctetStr:
				if printable(c.vb.Raw) && len(c.vb.Raw) > 0 {
					strCount++
					uniq[c.vb.Str()] = true
				}
			case ber.TagCounter32, ber.TagCounter64, ber.TagGauge32:
				counterCount++
			case ber.TagInteger:
				if v := c.vb.Int(); v >= 0 && v <= 3 {
					statusLike++
				}
			}
		}
		n := len(cells)
		switch {
		case strCount == n && len(uniq) == n && out.Name == 0:
			out.Name = col
		case counterCount == n:
			counterCols = append(counterCols, col)
		case statusLike == n && out.Status == 0:
			out.Status = col
		}
	}

	// In fgVpnTunEntTable the in/out octet counters are an adjacent pair; take
	// the lowest adjacent pair among the counter-valued columns.
	sort.Slice(counterCols, func(i, j int) bool { return counterCols[i] < counterCols[j] })
	for i := 0; i+1 < len(counterCols); i++ {
		if counterCols[i+1] == counterCols[i]+1 {
			out.In, out.Out = counterCols[i], counterCols[i+1]
			break
		}
	}
	if out.In == 0 && len(counterCols) >= 2 {
		out.In, out.Out = counterCols[0], counterCols[1]
	}

	out.RowCount = len(cols[out.Name])
	out.Confident = out.Name != 0 && out.In != 0 && out.Out != 0 && out.Status != 0
	switch {
	case out.Confident:
		out.Notes = fmt.Sprintf("detected from %d columns of live data", len(cols))
	case out.Name == 0:
		out.Notes = "could not identify the phase-2 name column; set it manually"
	case out.In == 0:
		out.Notes = "could not identify the octet counter columns; set them manually"
	default:
		out.Notes = "status column not identified; tunnels will be treated as up whenever counters are readable"
	}

	// Materialize the rows using the detected columns.
	var tunnels []Tunnel
	if out.Name != 0 {
		byRow := map[int]*Tunnel{}
		for _, c := range cols[out.Name] {
			byRow[c.row] = &Tunnel{Index: c.row, Name: c.vb.Str(), Up: true}
		}
		for col, cells := range cols {
			for _, c := range cells {
				t, ok := byRow[c.row]
				if !ok {
					continue
				}
				switch col {
				case out.In:
					t.In = c.vb.Uint()
				case out.Out:
					t.Out = c.vb.Uint()
				case out.Status:
					t.Status = int(c.vb.Int())
					t.Up = int64(t.Status) == out.UpValue
				}
			}
		}
		for _, t := range byRow {
			tunnels = append(tunnels, *t)
		}
		sort.Slice(tunnels, func(i, j int) bool { return tunnels[i].Name < tunnels[j].Name })
	}
	return out, tunnels, nil
}

// Run performs a full inventory: identity, interfaces and tunnels.
func Run(cl *snmp.Client, vpnBaseOID string) (*Result, error) {
	id, err := Probe(cl)
	if err != nil {
		return nil, err
	}
	res := &Result{Identity: id}

	ifs, warns, err := Interfaces(cl)
	if err != nil {
		return nil, err
	}
	res.Interfaces = ifs
	res.Warnings = append(res.Warnings, warns...)

	if vpnBaseOID == "" {
		vpnBaseOID = "1.3.6.1.4.1.12356.101.12.2.2.1"
	}
	vpn, tuns, err := DetectVPN(cl, vpnBaseOID)
	if err != nil {
		res.Warnings = append(res.Warnings, err.Error())
	}
	res.VPN = vpn
	res.Tunnels = tuns
	return res, nil
}

func last(o []uint32) int {
	if len(o) == 0 {
		return -1
	}
	return int(o[len(o)-1])
}

func printable(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}
