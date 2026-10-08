package main

import (
	"testing"
	"time"
)

func TestMergeTicketsKeepsConcurrentChanges(t *testing.T) {
	now := time.Now()
	// What `unlock` loaded before its round trips: vm1 and vm2.
	ours := clientConfig{Gateways: map[string]*profile{
		"vm1": {Gateway: "a", Token: "old", Ticket: "t1", TicketExpires: now.Add(12 * time.Hour)},
		"vm2": {Gateway: "b", Token: "old"},
	}}
	// What the file holds now: vm2 got a new token, vm3 was added by `login`.
	fresh := clientConfig{Gateways: map[string]*profile{
		"vm1": {Gateway: "a", Token: "old"},
		"vm2": {Gateway: "b", Token: "new"},
		"vm3": {Gateway: "c", Token: "x"},
	}}
	mergeTickets(fresh, ours)
	if g := fresh.Gateways["vm1"]; g.Ticket != "t1" {
		t.Fatalf("new ticket lost: %+v", g)
	}
	if fresh.Gateways["vm2"].Token != "new" || fresh.Gateways["vm3"] == nil {
		t.Fatal("a change made while unlock ran was overwritten")
	}
	// A gateway removed meanwhile stays removed.
	delete(fresh.Gateways, "vm1")
	mergeTickets(fresh, ours)
	if fresh.Gateways["vm1"] != nil {
		t.Fatal("a removed gateway came back")
	}
}
