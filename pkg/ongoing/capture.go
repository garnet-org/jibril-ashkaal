package ongoing

import "encoding/json"

type CaptureTelemetry struct {
	EventsLost          *int64 `json:"events_lost,omitempty"`
	EventsDropped       *int64 `json:"events_dropped,omitempty"`
	DrainDiscarded      *int64 `json:"drain_discarded,omitempty"`
	AttachFailures      *int64 `json:"attach_failures,omitempty"`
	ReadyBeforeWorkload *bool  `json:"ready_before_workload,omitempty"`
	invalidFields       map[string]json.RawMessage
	invalidObject       json.RawMessage
}

func (c *CaptureTelemetry) UnmarshalJSON(data []byte) error {
	*c = CaptureTelemetry{}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		c.invalidObject = append(json.RawMessage(nil), data...)
		return nil
	}
	for name, target := range map[string]any{
		"events_lost": &c.EventsLost, "events_dropped": &c.EventsDropped,
		"drain_discarded": &c.DrainDiscarded, "attach_failures": &c.AttachFailures,
		"ready_before_workload": &c.ReadyBeforeWorkload,
	} {
		raw, present := fields[name]
		if !present {
			continue
		}
		if err := json.Unmarshal(raw, target); err == nil && string(raw) != "null" {
			continue
		}
		switch target := target.(type) {
		case **int64:
			*target = nil
		case **bool:
			*target = nil
		}
		if c.invalidFields == nil {
			c.invalidFields = make(map[string]json.RawMessage)
		}
		c.invalidFields[name] = raw
	}
	return nil
}

func (c CaptureTelemetry) MarshalJSON() ([]byte, error) {
	if c.invalidObject != nil {
		return c.invalidObject, nil
	}
	type captureFields CaptureTelemetry
	data, err := json.Marshal(captureFields(c))
	if err != nil || len(c.invalidFields) == 0 {
		return data, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, err
	}
	for name, raw := range c.invalidFields {
		fields[name] = raw
	}
	return json.Marshal(fields)
}

func (c *CaptureTelemetry) Clone() *CaptureTelemetry {
	if c == nil {
		return nil
	}
	cloned := *c
	if c.EventsLost != nil {
		cloned.EventsLost = new(*c.EventsLost)
	}
	if c.EventsDropped != nil {
		cloned.EventsDropped = new(*c.EventsDropped)
	}
	if c.DrainDiscarded != nil {
		cloned.DrainDiscarded = new(*c.DrainDiscarded)
	}
	if c.AttachFailures != nil {
		cloned.AttachFailures = new(*c.AttachFailures)
	}
	if c.ReadyBeforeWorkload != nil {
		cloned.ReadyBeforeWorkload = new(*c.ReadyBeforeWorkload)
	}
	if c.invalidFields != nil {
		cloned.invalidFields = make(map[string]json.RawMessage, len(c.invalidFields))
		for name, raw := range c.invalidFields {
			cloned.invalidFields[name] = append(json.RawMessage(nil), raw...)
		}
	}
	cloned.invalidObject = append(json.RawMessage(nil), c.invalidObject...)
	return &cloned
}
