package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

func fetchState(client *http.Client, addr string) (*StateReply, error) {
	resp, err := client.Get(addr + "/raft/state")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %s", resp.Status)
	}
	var st StateReply
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		return nil, err
	}
	return &st, nil
}

func proposeCommand(client *http.Client, addr string, cmd string) (*ProposeReply, error) {
	body, err := json.Marshal(ProposeArgs{Command: cmd})
	if err != nil {
		return nil, err
	}
	resp, err := client.Post(addr+"/raft/propose", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %s", resp.Status)
	}
	var reply ProposeReply
	if err := json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return nil, err
	}
	return &reply, nil
}

func formatEntries(entries []LogEntry) string {
	var parts []string
	for _, e := range entries {
		if e.Index == 0 {
			continue
		}
		parts = append(parts, fmt.Sprintf("%d:%s@t%d", e.Index, e.Command, e.Term))
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func formatApplied(entries []AppliedEntry) string {
	var parts []string
	for _, e := range entries {
		parts = append(parts, fmt.Sprintf("%d:%s", e.Index, e.Command))
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func main() {
	numNodes := flag.Int("nodes", 3, "number of Raft nodes in the cluster")
	numProposals := flag.Int("proposals", 4, "number of pipelined client proposals")
	verbose := flag.Bool("verbose", false, "enable verbose Raft node logs")
	flag.Parse()

	nodes := make([]*RaftNode, *numNodes)
	addrs := make(map[int]string, *numNodes)

	for i := 0; i < *numNodes; i++ {
		node, addr, err := NewRaftNode(i, *verbose)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to start Raft node %d: %v\n", i, err)
			os.Exit(2)
		}
		nodes[i] = node
		addrs[i] = addr
	}
	defer func() {
		for _, n := range nodes {
			n.Stop()
		}
	}()

	for _, n := range nodes {
		n.SetPeers(addrs)
	}
	for _, n := range nodes {
		n.Start()
	}

	client := &http.Client{
		Transport: &http.Transport{DisableKeepAlives: true},
		Timeout:   200 * time.Millisecond,
	}

	// 1. Wait for a leader to be elected via REST state queries.
	var leaderID = -1
	var leaderAddr string
	for attempt := 0; attempt < 30; attempt++ {
		time.Sleep(25 * time.Millisecond)
		for i := 0; i < *numNodes; i++ {
			st, err := fetchState(client, addrs[i])
			if err == nil && st.Role == RoleLeader {
				leaderID = i
				leaderAddr = addrs[i]
				break
			}
		}
		if leaderID != -1 {
			break
		}
	}

	if leaderID == -1 {
		fmt.Fprintln(os.Stderr, "FAIL: Cluster failed to elect a leader within timeout")
		os.Exit(1)
	}

	fmt.Printf("Leader elected: node %d (%s)\n", leaderID, leaderAddr)

	// 2. Submit pipelined client commands over REST (`POST /raft/propose`).
	expectedCmds := make([]string, 0, *numProposals)
	for i := 1; i <= *numProposals; i++ {
		cmd := fmt.Sprintf("SET k=%d", i)
		reply, err := proposeCommand(client, leaderAddr, cmd)
		if err != nil || !reply.Success {
			fmt.Fprintf(os.Stderr, "FAIL: Proposal %q failed: err=%v reply=%+v\n", cmd, err, reply)
			os.Exit(1)
		}
		expectedCmds = append(expectedCmds, cmd)
	}

	// 3. Wait for replication and at least one heartbeat cycle to settle.
	time.Sleep(90 * time.Millisecond)

	// 4. Query all nodes via `GET /raft/state` and verify Raft safety invariants.
	states := make([]*StateReply, *numNodes)
	for i := 0; i < *numNodes; i++ {
		st, err := fetchState(client, addrs[i])
		if err != nil {
			fmt.Fprintf(os.Stderr, "FAIL: Could not query state of node %d: %v\n", i, err)
			os.Exit(1)
		}
		states[i] = st
	}

	fmt.Println("\nCluster State Summary:")
	for _, st := range states {
		fmt.Printf("  node %d (%-9s term=%d commit=%d applied=%d): log=%s applied=%s\n",
			st.ID, st.Role, st.Term, st.CommitIndex, st.LastApplied,
			formatEntries(st.Log), formatApplied(st.Applied))
	}

	// Check Invariant 1: Election Safety (at most one leader per term).
	leadersByTerm := make(map[int]int)
	for _, st := range states {
		if st.Role == RoleLeader {
			if prev, exists := leadersByTerm[st.Term]; exists && prev != st.ID {
				fmt.Fprintf(os.Stderr, "\nINVARIANT VIOLATION (Election Safety): Multiple leaders (%d and %d) in term %d!\n",
					prev, st.ID, st.Term)
				os.Exit(1)
			}
			leadersByTerm[st.Term] = st.ID
		}
	}

	// Check Invariant 2: State Machine Safety (no two nodes apply different commands at the same index).
	appliedByIndex := make(map[int]struct {
		nodeID int
		cmd    string
	})
	for _, st := range states {
		for _, app := range st.Applied {
			if prev, exists := appliedByIndex[app.Index]; exists && prev.cmd != app.Command {
				fmt.Fprintf(os.Stderr,
					"\nINVARIANT VIOLATION (State Machine Safety): node %d applied %q at index %d, but node %d applied %q!\n",
					prev.nodeID, prev.cmd, app.Index, st.ID, app.Command)
				os.Exit(1)
			}
			appliedByIndex[app.Index] = struct {
				nodeID int
				cmd    string
			}{nodeID: st.ID, cmd: app.Command}
		}
	}

	// Check Invariant 3: Committed Log & State Machine Convergence
	// Every entry committed by the leader must be present in the follower logs and applied
	// after replication and heartbeat settlement.
	leaderState := states[leaderID]
	if leaderState.CommitIndex < *numProposals {
		fmt.Fprintf(os.Stderr,
			"\nINVARIANT VIOLATION (Commit Progress): leader node %d only committed %d/%d proposals!\n",
			leaderID, leaderState.CommitIndex, *numProposals)
		os.Exit(1)
	}

	for _, st := range states {
		if len(st.Log)-1 < leaderState.CommitIndex || st.LastApplied < leaderState.CommitIndex {
			fmt.Fprintf(os.Stderr,
				"\nINVARIANT VIOLATION (Committed Log Truncation Race): Leader node %d committed %d entries %s, "+
					"but follower node %d has truncated log %s (commitIndex=%d, lastApplied=%d)!\n"+
					"  -> Cause: Out-of-order AppendEntries RPCs caused an older RPC with fewer entries to overwrite\n"+
					"     a newer RPC's entries on node %d after the leader had already advanced matchIndex.\n",
				leaderID, leaderState.CommitIndex, formatEntries(leaderState.Log),
				st.ID, formatEntries(st.Log), st.CommitIndex, st.LastApplied, st.ID)
			os.Exit(1)
		}
		for idx := 1; idx <= *numProposals; idx++ {
			if st.Log[idx].Command != expectedCmds[idx-1] {
				fmt.Fprintf(os.Stderr,
					"\nINVARIANT VIOLATION (Log Matching): node %d has %q at index %d, expected %q!\n",
					st.ID, st.Log[idx].Command, idx, expectedCmds[idx-1])
				os.Exit(1)
			}
		}
	}

	fmt.Printf("\nOK: All %d proposals replicated, committed, and applied consistently across all %d nodes.\n",
		*numProposals, *numNodes)
}
