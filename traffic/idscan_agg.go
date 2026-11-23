package traffic

import (
	"sort"
)

// identityAgg accumulates per-host, per-list, per-task counts while a scan runs.
// It is deliberately single-goroutine: ScanIdentity processes batches serially,
// and deterministic ordering at materialisation is what makes reports diffable.
type identityAgg struct {
	allow     *IdentityAllowlist
	taskMap   map[string][]int64
	hosts     map[string]*identityHostAgg
	lists     map[string]*IdentityListStat
	exchanges map[string]map[string]bool

	findings      []IdentityFinding
	findingsTotal int64
	samples       []IdentitySample
	suppressed    map[string]*IdentitySuppressedRule
	suppressedNum int64
}

type identityHostAgg struct {
	stat           IdentityHostStat
	rules          map[string]bool
	samplesPerList map[string]int
}

func newIdentityAgg(allow *IdentityAllowlist, taskMap map[string][]int64) *identityAgg {
	a := &identityAgg{
		allow:      allow,
		taskMap:    map[string][]int64{},
		hosts:      map[string]*identityHostAgg{},
		lists:      map[string]*IdentityListStat{},
		exchanges:  map[string]map[string]bool{},
		suppressed: map[string]*IdentitySuppressedRule{},
	}
	for _, list := range []string{"A", "B", "C"} {
		a.lists[list] = &IdentityListStat{}
		a.exchanges[list] = map[string]bool{}
	}
	for h, ids := range taskMap {
		key := normalizeIdentityHost(h)
		if key == "" || len(ids) == 0 {
			continue
		}
		seen := map[int64]bool{}
		out := make([]int64, 0, len(ids))
		for _, id := range ids {
			if id <= 0 || seen[id] {
				continue
			}
			seen[id] = true
			out = append(out, id)
		}
		if len(out) == 0 {
			continue
		}
		sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
		a.taskMap[key] = out
	}
	return a
}

func (a *identityAgg) host(name string) *identityHostAgg {
	key := normalizeIdentityHost(name)
	if key == "" {
		key = "(unknown)"
	}
	h := a.hosts[key]
	if h == nil {
		h = &identityHostAgg{
			stat: IdentityHostStat{
				Host: key,
				Hits: map[string]int64{"A": 0, "B": 0, "C": 0},
			},
			rules:          map[string]bool{},
			samplesPerList: map[string]int{},
		}
		a.hosts[key] = h
	}
	return h
}

func (a *identityAgg) observe(host string)  { a.host(host).stat.Exchanges++ }
func (a *identityAgg) eligible(host string) { a.host(host).stat.Eligible++ }
func (a *identityAgg) withBody(host string) { a.host(host).stat.WithBody++ }

func (a *identityAgg) suppresses(termID, host string) (*IdentityAllowRule, bool) {
	if a.allow == nil {
		return nil, false
	}
	return a.allow.match(termID, host)
}

func (a *identityAgg) suppress(rule *IdentityAllowRule) {
	key := rule.TermID + "\x00" + rule.Host + "\x00" + rule.Reason
	r := a.suppressed[key]
	if r == nil {
		r = &IdentitySuppressedRule{TermID: rule.TermID, Host: rule.Host, Reason: rule.Reason}
		a.suppressed[key] = r
	}
	r.Count++
	a.suppressedNum++
}

func (a *identityAgg) addHit(row identityRow, rec identityHitRecord) {
	h := a.host(row.host)
	h.stat.Hits[rec.term.List]++
	a.lists[rec.term.List].Hits++
	h.rules[rec.term.ID] = true
	if !a.exchanges[rec.term.List][row.id] {
		a.exchanges[rec.term.List][row.id] = true
		a.lists[rec.term.List].Exchanges++
	}
	if len(a.samples) >= identitySamplesCap {
		return
	}
	if h.samplesPerList[rec.term.List] >= identitySamplesPerHostList {
		return
	}
	s := identityMakeSample(row, rec)
	h.stat.Samples = append(h.stat.Samples, s)
	a.samples = append(a.samples, s)
	h.samplesPerList[rec.term.List]++
}

// promote turns unsuppressed hits into findings. Any A hit is a finding; two
// distinct B terms in the same exchange promote to a medium finding. A lone B is
// intentionally not promoted: tool names are generic enough to appear in benign
// pages, and the co-occurrence requirement is the false-positive gate.
func (a *identityAgg) promote(row identityRow, recs []identityHitRecord) {
	var bRecs []identityHitRecord
	for _, rec := range recs {
		switch rec.term.List {
		case "A":
			a.addFinding(identityFindingFrom(row, rec, nil))
		case "B":
			bRecs = append(bRecs, rec)
		}
	}
	if len(bRecs) < 2 {
		return
	}
	terms := make([]string, 0, len(bRecs))
	for _, rec := range bRecs {
		terms = append(terms, rec.term.ID)
	}
	sort.Strings(terms)
	a.addFinding(identityFindingFrom(row, bRecs[0], terms))
}

func (a *identityAgg) addFinding(f IdentityFinding) {
	a.findingsTotal++
	a.host(f.Host).stat.Findings++
	a.lists[f.List].Findings++
	if len(a.findings) < identityFindingsCap {
		a.findings = append(a.findings, f)
	}
}

func identityMakeSample(row identityRow, rec identityHitRecord) IdentitySample {
	return IdentitySample{
		ExchangeID: row.id,
		TS:         row.ts,
		Host:       normalizeIdentityHost(row.host),
		List:       rec.term.List,
		TermID:     rec.term.ID,
		Where:      rec.where,
		Offset:     rec.offset,
		Snippet:    renderIdentitySample(rec.text, rec.offset, rec.offset+len(rec.term.Pattern), rec.term.ID),
	}
}

func identityFindingFrom(row identityRow, rec identityHitRecord, terms []string) IdentityFinding {
	severity := "high"
	if rec.term.List == "B" {
		severity = "medium"
	}
	return IdentityFinding{
		ExchangeID: row.id,
		TS:         row.ts,
		Host:       normalizeIdentityHost(row.host),
		List:       rec.term.List,
		TermID:     rec.term.ID,
		Terms:      terms,
		Where:      rec.where,
		Offset:     rec.offset,
		Snippet:    renderIdentitySample(rec.text, rec.offset, rec.offset+len(rec.term.Pattern), rec.term.ID),
		Severity:   severity,
	}
}

func (a *identityAgg) listStats() map[string]IdentityListStat {
	out := make(map[string]IdentityListStat, len(a.lists))
	for list, stat := range a.lists {
		out[list] = *stat
	}
	return out
}

func (a *identityAgg) hostStats() []IdentityHostStat {
	names := make([]string, 0, len(a.hosts))
	for name := range a.hosts {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]IdentityHostStat, 0, len(names))
	for _, name := range names {
		h := a.hosts[name]
		for _, list := range []string{"A", "B", "C"} {
			if _, ok := h.stat.Hits[list]; !ok {
				h.stat.Hits[list] = 0
			}
		}
		h.stat.Rules = h.stat.Rules[:0]
		for id := range h.rules {
			h.stat.Rules = append(h.stat.Rules, id)
		}
		sort.Strings(h.stat.Rules)
		sort.Slice(h.stat.Samples, func(i, j int) bool { return identityLessSample(h.stat.Samples[i], h.stat.Samples[j]) })
		out = append(out, h.stat)
	}
	return out
}

func (a *identityAgg) sampleList() []IdentitySample {
	out := append([]IdentitySample(nil), a.samples...)
	sort.Slice(out, func(i, j int) bool { return identityLessSample(out[i], out[j]) })
	return out
}

func identityLessSample(a, b IdentitySample) bool {
	if a.Host != b.Host {
		return a.Host < b.Host
	}
	if a.List != b.List {
		return a.List < b.List
	}
	if a.TermID != b.TermID {
		return a.TermID < b.TermID
	}
	if a.ExchangeID != b.ExchangeID {
		return a.ExchangeID < b.ExchangeID
	}
	if a.Where != b.Where {
		return a.Where < b.Where
	}
	return a.Offset < b.Offset
}

func (a *identityAgg) findingList() []IdentityFinding {
	out := append([]IdentityFinding(nil), a.findings...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		if out[i].ExchangeID != out[j].ExchangeID {
			return out[i].ExchangeID < out[j].ExchangeID
		}
		if out[i].List != out[j].List {
			return out[i].List < out[j].List
		}
		if out[i].TermID != out[j].TermID {
			return out[i].TermID < out[j].TermID
		}
		if out[i].Where != out[j].Where {
			return out[i].Where < out[j].Where
		}
		return out[i].Offset < out[j].Offset
	})
	return out
}

func (a *identityAgg) taskStats() []IdentityTaskStat {
	if len(a.taskMap) == 0 {
		return nil
	}
	acc := map[int64]*IdentityTaskStat{}
	for _, hs := range a.hostStats() {
		ids := a.taskMap[hs.Host]
		if len(ids) == 0 {
			continue
		}
		for _, id := range ids {
			t := acc[id]
			if t == nil {
				t = &IdentityTaskStat{TaskID: id, Hits: map[string]int64{"A": 0, "B": 0, "C": 0}}
				acc[id] = t
			}
			t.Hosts = append(t.Hosts, hs.Host)
			for list, n := range hs.Hits {
				t.Hits[list] += n
			}
			t.Findings += hs.Findings
			if len(ids) > 1 {
				t.Shared = true
			}
		}
	}
	ids := make([]int64, 0, len(acc))
	for id := range acc {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	out := make([]IdentityTaskStat, 0, len(ids))
	for _, id := range ids {
		t := acc[id]
		sort.Strings(t.Hosts)
		out = append(out, *t)
	}
	return out
}

func (a *identityAgg) unmappedHosts() []string {
	if len(a.taskMap) == 0 {
		return nil
	}
	var out []string
	for host := range a.hosts {
		if len(a.taskMap[host]) == 0 {
			out = append(out, host)
		}
	}
	sort.Strings(out)
	return out
}

func (a *identityAgg) suppressedReport() IdentitySuppressed {
	out := IdentitySuppressed{ByAllowlist: a.suppressedNum}
	for _, r := range a.suppressed {
		out.Rules = append(out.Rules, *r)
	}
	sort.Slice(out.Rules, func(i, j int) bool {
		if out.Rules[i].TermID != out.Rules[j].TermID {
			return out.Rules[i].TermID < out.Rules[j].TermID
		}
		if out.Rules[i].Host != out.Rules[j].Host {
			return out.Rules[i].Host < out.Rules[j].Host
		}
		return out.Rules[i].Reason < out.Rules[j].Reason
	})
	return out
}
