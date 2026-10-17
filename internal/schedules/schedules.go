// Package schedules implements time-windowed protection profiles.
//
// A schedule targets a policy group or a single client and applies an effect
// while active: temporarily disabling protection, or enabling an extra set of
// blocklists. Evaluation is stateless: Active consults the schedule's stored
// fields and the given time, so decisions are correct after restarts and the
// database row is always authoritative.
package schedules

import (
	"encoding/json"
	"fmt"
	"time"
)

// Effect kinds.
const (
	// EffectProtectionOff disables filtering for the target while active.
	EffectProtectionOff = "protection_off"
	// EffectProtectionOn forces filtering for the target while active, even
	// if the group was disabled.
	EffectProtectionOn = "protection_on"
	// EffectExtraLists enables additional blocklists (effect_data: list ids).
	EffectExtraLists = "extra_lists"
)

// Target kinds.
const (
	TargetAll    = "all"
	TargetGroup  = "group"
	TargetClient = "client"
)

// Schedule is a recurring time window with an effect.
type Schedule struct {
	ID          int64   `json:"id"`
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Enabled     bool    `json:"enabled"`
	TZ          string  `json:"tz"`        // IANA name, e.g. "Europe/Istanbul"
	DaysMask    int     `json:"days_mask"` // bit i = weekday i (Sunday=0)
	StartMin    int     `json:"start_min"` // minutes after midnight, [0,1439]
	EndMin      int     `json:"end_min"`   // may be < StartMin (crosses midnight)
	DateFrom    string  `json:"date_from"` // optional YYYY-MM-DD
	DateTo      string  `json:"date_to"`
	TargetKind  string  `json:"target_kind"`
	TargetID    int64   `json:"target_id"`
	Effect      string  `json:"effect"`
	ListIDs     []int64 `json:"list_ids,omitempty"` // for EffectExtraLists
	CreatedAt   string  `json:"created_at"`
	UpdatedAt   string  `json:"updated_at"`
}

// Validate checks the schedule fields.
func (s *Schedule) Validate() map[string]string {
	errs := map[string]string{}
	if s.Name == "" {
		errs["name"] = "name is required"
	}
	if len(s.Name) > 80 {
		errs["name"] = "name too long"
	}
	if _, err := time.LoadLocation(s.TZ); err != nil {
		errs["tz"] = "unknown IANA time zone"
	}
	if s.DaysMask < 1 || s.DaysMask > 127 {
		errs["days_mask"] = "select at least one day"
	}
	if s.StartMin < 0 || s.StartMin > 1439 || s.EndMin < 0 || s.EndMin > 1439 {
		errs["times"] = "times must be minutes 0-1439"
	}
	for _, d := range []struct{ k, v string }{{"date_from", s.DateFrom}, {"date_to", s.DateTo}} {
		if d.v != "" {
			if _, err := time.Parse("2006-01-02", d.v); err != nil {
				errs[d.k] = "expected YYYY-MM-DD"
			}
		}
	}
	if s.DateFrom != "" && s.DateTo != "" && s.DateFrom > s.DateTo {
		errs["date_to"] = "end date is before start date"
	}
	switch s.TargetKind {
	case TargetAll, TargetGroup, TargetClient:
	default:
		errs["target_kind"] = "target must be all, group or client"
	}
	if s.TargetKind != TargetAll && s.TargetID <= 0 {
		errs["target_id"] = "a target is required"
	}
	switch s.Effect {
	case EffectProtectionOff, EffectProtectionOn:
	case EffectExtraLists:
		if len(s.ListIDs) == 0 {
			errs["list_ids"] = "choose at least one blocklist"
		}
	default:
		errs["effect"] = "unknown effect"
	}
	return errs
}

// Active reports whether the schedule is in effect at time t. UTC timestamps
// stored in the DB are converted into the schedule's zone for evaluation so
// DST transitions follow the configured zone, not the host's.
func (s *Schedule) Active(t time.Time) bool {
	if !s.Enabled {
		return false
	}
	loc, err := time.LoadLocation(s.TZ)
	if err != nil {
		loc = time.UTC
	}
	lt := t.In(loc)
	today := lt.Format("2006-01-02")
	if s.DateFrom != "" && today < s.DateFrom {
		return false
	}
	if s.DateTo != "" && today > s.DateTo {
		return false
	}
	min := lt.Hour()*60 + lt.Minute()
	wd := int(lt.Weekday())
	if s.StartMin <= s.EndMin {
		// Same-day window.
		if min < s.StartMin || min >= s.EndMin {
			return false
		}
		return s.DaysMask&(1<<wd) != 0
	}
	// Overnight window: e.g. 22:00-07:00. The active portion is attributed to
	// the day on which it started — so before midnight we check today's mask,
	// after midnight (still inside the window) we check yesterday's.
	if min >= s.StartMin {
		return s.DaysMask&(1<<wd) != 0
	}
	if min < s.EndMin {
		return s.DaysMask&(1<<((wd+6)%7)) != 0
	}
	return false
}

// Applies reports whether this schedule targets the given subject.
func (s *Schedule) Applies(clientID, groupID int64) bool {
	switch s.TargetKind {
	case TargetAll:
		return true
	case TargetClient:
		return s.TargetID == clientID
	case TargetGroup:
		return s.TargetID == groupID
	}
	return false
}

// Transition describes the next (or most recent) start/end boundary.
type Transition struct {
	At       time.Time `json:"at"`
	ToActive bool      `json:"to_active"`
}

// NextTransition finds the next time after t at which Active() would flip,
// by scanning minute boundaries within the schedule's window and horizon.
// Used by the UI to show "next change"; bounded to 8 days.
func (s *Schedule) NextTransition(t time.Time) (Transition, bool) {
	if !s.Enabled {
		return Transition{}, false
	}
	cur := s.Active(t)
	for i := 1; i <= 8*24*60; i++ {
		cand := t.Truncate(time.Minute).Add(time.Duration(i) * time.Minute)
		if s.Active(cand) != cur {
			return Transition{At: cand, ToActive: !cur}, true
		}
	}
	return Transition{}, false
}

// DecodeListIDs parses effect_data for extra_lists schedules.
func DecodeListIDs(raw string) []int64 {
	if raw == "" {
		return nil
	}
	var ids []int64
	if err := json.Unmarshal([]byte(raw), &ids); err != nil {
		return nil
	}
	return ids
}

// EncodeListIDs serializes list ids into effect_data.
func EncodeListIDs(ids []int64) string {
	b, _ := json.Marshal(ids)
	return string(b)
}

// MinuteOfDay formats a minute count as HH:MM.
func MinuteOfDay(m int) string { return fmt.Sprintf("%02d:%02d", m/60, m%60) }
