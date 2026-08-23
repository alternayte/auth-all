package events

import (
	"context"
	"testing"
	"time"
)

func TestEmitterFansOut(t *testing.T) {
	now := time.Now()
	e := NewEmitter(func() time.Time { return now })
	var got []Event
	e.Add(HandlerFunc(func(_ context.Context, ev Event) { got = append(got, ev) }))
	e.Add(HandlerFunc(func(_ context.Context, ev Event) { got = append(got, ev) }))
	e.Add(nil)
	e.Emit(context.Background(), SignIn, "user-1", map[string]any{"method": "email"})
	if len(got) != 2 {
		t.Fatalf("expected two deliveries, got %d", len(got))
	}
	if got[0].Name != SignIn || got[0].UserID != "user-1" || !got[0].Time.Equal(now) {
		t.Fatalf("unexpected event %+v", got[0])
	}
}
