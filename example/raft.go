package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"sync"
	"time"
)

type Role string

const (
	RoleFollower  Role = "Follower"
	RoleCandidate Role = "Candidate"
	RoleLeader    Role = "Leader"
)

// LogEntry represents a single replicated state machine command in the Raft log.
// Index is 1-based (index 0 is a dummy sentinel entry at term 0).
type LogEntry struct {
	Index   int    `json:"index"`
	Term    int    `json:"term"`
	Command string `json:"command"`
}

// AppliedEntry records a command committed and applied to the node's state machine.
type AppliedEntry struct {
	Index   int    `json:"index"`
	Term    int    `json:"term"`
	Command string `json:"command"`
}

type RequestVoteArgs struct {
	Term         int `json:"term"`
	CandidateID  int `json:"candidate_id"`
	LastLogIndex int `json:"last_log_index"`
	LastLogTerm  int `json:"last_log_term"`
}

type RequestVoteReply struct {
	Term        int  `json:"term"`
	VoteGranted bool `json:"vote_granted"`
}

type AppendEntriesArgs struct {
	Term         int        `json:"term"`
	LeaderID     int        `json:"leader_id"`
	PrevLogIndex int        `json:"prev_log_index"`
	PrevLogTerm  int        `json:"prev_log_term"`
	Entries      []LogEntry `json:"entries"`
	LeaderCommit int        `json:"leader_commit"`
}

type AppendEntriesReply struct {
	Term    int  `json:"term"`
	Success bool `json:"success"`
}

type ProposeArgs struct {
	Command string `json:"command"`
}

type ProposeReply struct {
	Success  bool   `json:"success"`
	Index    int    `json:"index"`
	Term     int    `json:"term"`
	LeaderID int    `json:"leader_id"`
	Error    string `json:"error,omitempty"`
}

type StateReply struct {
	ID          int            `json:"id"`
	Addr        string         `json:"addr"`
	Term        int            `json:"term"`
	Role        Role           `json:"role"`
	VotedFor    int            `json:"voted_for"`
	CommitIndex int            `json:"commit_index"`
	LastApplied int            `json:"last_applied"`
	Log         []LogEntry     `json:"log"`
	Applied     []AppliedEntry `json:"applied"`
}

// RaftNode implements a Raft consensus node communicating via HTTP/REST.
type RaftNode struct {
	mu sync.Mutex

	id    int
	addr  string
	peers map[int]string // peer ID -> "http://127.0.0.1:port"

	// Persistent state on all servers
	currentTerm int
	votedFor    int
	log         []LogEntry

	// Volatile state on all servers
	role          Role
	leaderID      int
	commitIndex   int
	lastApplied   int
	applied       []AppliedEntry
	lastHeartbeat time.Time

	// Volatile state on leaders
	nextIndex  map[int]int
	matchIndex map[int]int

	httpServer *http.Server
	httpClient *http.Client
	stopCh     chan struct{}
	stopped    bool
	verbose    bool
}

func NewRaftNode(id int, verbose bool) (*RaftNode, string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "", err
	}
	addr := "http://" + ln.Addr().String()

	// Disable HTTP keep-alive connection reuse so each concurrent RPC uses its own
	// TCP socket, making concurrent RPC interleavings explicit over loopback.
	transport := &http.Transport{
		DisableKeepAlives: true,
	}

	n := &RaftNode{
		id:            id,
		addr:          addr,
		peers:         make(map[int]string),
		currentTerm:   0,
		votedFor:      -1,
		log:           []LogEntry{{Index: 0, Term: 0, Command: ""}}, // sentinel entry at index 0
		role:          RoleFollower,
		leaderID:      -1,
		commitIndex:   0,
		lastApplied:   0,
		lastHeartbeat: time.Now(),
		nextIndex:     make(map[int]int),
		matchIndex:    make(map[int]int),
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   150 * time.Millisecond,
		},
		stopCh:  make(chan struct{}),
		verbose: verbose,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/raft/request-vote", n.handleRequestVote)
	mux.HandleFunc("/raft/append-entries", n.handleAppendEntries)
	mux.HandleFunc("/raft/propose", n.handlePropose)
	mux.HandleFunc("/raft/state", n.handleState)

	n.httpServer = &http.Server{Handler: mux}
	go func() {
		_ = n.httpServer.Serve(ln)
	}()

	return n, addr, nil
}

func (n *RaftNode) SetPeers(peers map[int]string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for id, addr := range peers {
		if id != n.id {
			n.peers[id] = addr
		}
	}
}

func (n *RaftNode) Start() {
	go n.electionLoop()
	go n.heartbeatLoop()
}

func (n *RaftNode) Stop() {
	n.mu.Lock()
	if n.stopped {
		n.mu.Unlock()
		return
	}
	n.stopped = true
	close(n.stopCh)
	n.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_ = n.httpServer.Shutdown(ctx)
}

func (n *RaftNode) lastLogIndexAndTermLocked() (int, int) {
	last := n.log[len(n.log)-1]
	return last.Index, last.Term
}

func (n *RaftNode) stepDownLocked(newTerm int) {
	n.currentTerm = newTerm
	n.role = RoleFollower
	n.votedFor = -1
}

func (n *RaftNode) applyCommittedLocked() {
	for n.lastApplied < n.commitIndex && n.lastApplied+1 < len(n.log) {
		n.lastApplied++
		entry := n.log[n.lastApplied]
		n.applied = append(n.applied, AppliedEntry{
			Index:   entry.Index,
			Term:    entry.Term,
			Command: entry.Command,
		})
		if n.verbose {
			fmt.Printf("[node %d] applied index=%d term=%d cmd=%q\n", n.id, entry.Index, entry.Term, entry.Command)
		}
	}
}

// electionLoop monitors election timeouts and triggers leader elections.
func (n *RaftNode) electionLoop() {
	for {
		timeout := time.Duration(80+rand.Intn(80)) * time.Millisecond
		timer := time.NewTimer(timeout)
		select {
		case <-n.stopCh:
			timer.Stop()
			return
		case <-timer.C:
		}

		n.mu.Lock()
		if n.stopped {
			n.mu.Unlock()
			return
		}
		if n.role != RoleLeader && time.Since(n.lastHeartbeat) >= timeout {
			n.startElectionLocked()
		}
		n.mu.Unlock()
	}
}

func (n *RaftNode) startElectionLocked() {
	n.role = RoleCandidate
	n.currentTerm++
	n.votedFor = n.id
	n.lastHeartbeat = time.Now()

	savedTerm := n.currentTerm
	lastLogIdx, lastLogTerm := n.lastLogIndexAndTermLocked()
	peers := make(map[int]string, len(n.peers))
	for id, addr := range n.peers {
		peers[id] = addr
	}

	if n.verbose {
		fmt.Printf("[node %d] starting election for term %d\n", n.id, savedTerm)
	}

	votes := 1
	totalNodes := len(peers) + 1

	for _, peerAddr := range peers {
		go func(paddr string) {
			args := RequestVoteArgs{
				Term:         savedTerm,
				CandidateID:  n.id,
				LastLogIndex: lastLogIdx,
				LastLogTerm:  lastLogTerm,
			}
			var reply RequestVoteReply
			if err := n.postJSON(paddr+"/raft/request-vote", args, &reply); err != nil {
				return
			}

			n.mu.Lock()
			defer n.mu.Unlock()
			if n.stopped {
				return
			}
			if reply.Term > n.currentTerm {
				n.stepDownLocked(reply.Term)
				return
			}
			if n.role != RoleCandidate || n.currentTerm != savedTerm {
				return
			}
			if reply.VoteGranted {
				votes++
				if votes > totalNodes/2 && n.role == RoleCandidate {
					n.becomeLeaderLocked()
				}
			}
		}(peerAddr)
	}
}

func (n *RaftNode) becomeLeaderLocked() {
	n.role = RoleLeader
	n.leaderID = n.id
	nextIdx := len(n.log)
	for peerID := range n.peers {
		n.nextIndex[peerID] = nextIdx
		n.matchIndex[peerID] = 0
	}
	if n.verbose {
		fmt.Printf("[node %d] became Leader for term %d (nextIndex=%d)\n", n.id, n.currentTerm, nextIdx)
	}
	n.broadcastAppendEntriesLocked()
}

func (n *RaftNode) heartbeatLoop() {
	ticker := time.NewTicker(30 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-n.stopCh:
			return
		case <-ticker.C:
			n.mu.Lock()
			if n.stopped {
				n.mu.Unlock()
				return
			}
			if n.role == RoleLeader {
				n.broadcastAppendEntriesLocked()
			}
			n.mu.Unlock()
		}
	}
}

// broadcastAppendEntriesLocked sends AppendEntries RPCs to all peers.
func (n *RaftNode) broadcastAppendEntriesLocked() {
	for peerID, peerAddr := range n.peers {
		prevIdx := n.nextIndex[peerID] - 1
		if prevIdx < 0 {
			prevIdx = 0
		}
		if prevIdx >= len(n.log) {
			prevIdx = len(n.log) - 1
		}
		prevTerm := n.log[prevIdx].Term
		entries := make([]LogEntry, len(n.log[prevIdx+1:]))
		copy(entries, n.log[prevIdx+1:])

		args := AppendEntriesArgs{
			Term:         n.currentTerm,
			LeaderID:     n.id,
			PrevLogIndex: prevIdx,
			PrevLogTerm:  prevTerm,
			Entries:      entries,
			LeaderCommit: n.commitIndex,
		}

		go n.sendAppendEntries(peerID, peerAddr, args)
	}
}

func (n *RaftNode) sendAppendEntries(peerID int, peerAddr string, args AppendEntriesArgs) {
	var reply AppendEntriesReply
	if err := n.postJSON(peerAddr+"/raft/append-entries", args, &reply); err != nil {
		return
	}

	n.mu.Lock()
	defer n.mu.Unlock()
	if n.stopped {
		return
	}
	if reply.Term > n.currentTerm {
		n.stepDownLocked(reply.Term)
		return
	}
	if n.role != RoleLeader || n.currentTerm != args.Term {
		return
	}

	if reply.Success {
		updatedMatch := args.PrevLogIndex + len(args.Entries)
		if updatedMatch > n.matchIndex[peerID] {
			n.matchIndex[peerID] = updatedMatch
			n.nextIndex[peerID] = updatedMatch + 1
		}

		// Advance commitIndex if a majority of nodes have replicated an entry from currentTerm.
		totalNodes := len(n.peers) + 1
		for idx := len(n.log) - 1; idx > n.commitIndex; idx-- {
			if n.log[idx].Term != n.currentTerm {
				continue
			}
			count := 1 // Leader itself
			for pid := range n.peers {
				if n.matchIndex[pid] >= idx {
					count++
				}
			}
			if count > totalNodes/2 {
				n.commitIndex = idx
				n.applyCommittedLocked()
				break
			}
		}
	} else {
		if n.nextIndex[peerID] > 1 {
			n.nextIndex[peerID]--
		}
	}
}

// HTTP Handlers

func (n *RaftNode) handleRequestVote(w http.ResponseWriter, r *http.Request) {
	var args RequestVoteArgs
	if err := json.NewDecoder(r.Body).Decode(&args); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	reply := RequestVoteReply{
		Term:        n.currentTerm,
		VoteGranted: false,
	}

	if args.Term < n.currentTerm {
		writeJSON(w, reply)
		return
	}
	if args.Term > n.currentTerm {
		n.stepDownLocked(args.Term)
	}

	lastIdx, lastTerm := n.lastLogIndexAndTermLocked()
	logUpToDate := args.LastLogTerm > lastTerm ||
		(args.LastLogTerm == lastTerm && args.LastLogIndex >= lastIdx)

	if (n.votedFor == -1 || n.votedFor == args.CandidateID) && logUpToDate {
		n.votedFor = args.CandidateID
		n.lastHeartbeat = time.Now()
		reply.VoteGranted = true
	}
	reply.Term = n.currentTerm
	writeJSON(w, reply)
}

func (n *RaftNode) handleAppendEntries(w http.ResponseWriter, r *http.Request) {
	var args AppendEntriesArgs
	if err := json.NewDecoder(r.Body).Decode(&args); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	reply := AppendEntriesReply{
		Term:    n.currentTerm,
		Success: false,
	}

	if args.Term < n.currentTerm {
		writeJSON(w, reply)
		return
	}

	if args.Term > n.currentTerm || n.role != RoleFollower {
		n.stepDownLocked(args.Term)
	}
	n.leaderID = args.LeaderID
	n.lastHeartbeat = time.Now()
	reply.Term = n.currentTerm

	if len(args.Entries) > 0 {
		// Verify log contains an entry at PrevLogIndex with PrevLogTerm.
		if args.PrevLogIndex >= len(n.log) || n.log[args.PrevLogIndex].Term != args.PrevLogTerm {
			writeJSON(w, reply)
			return
		}

		// INTENTIONAL BUG (Unconditional log truncation on out-of-order AppendEntries):
		// According to Raft Paper Figure 2 (AppendEntries receiver steps 3 & 4), a follower
		// MUST only delete existing entries if an existing entry conflicts with a new one
		// (same index, different term), and must keep any subsequent entries already present.
		//
		// Here, slicing `n.log[:args.PrevLogIndex+1]` and appending `args.Entries` works
		// whenever AppendEntries RPCs arrive in order. However, when the leader pipelines
		// multiple AppendEntries RPCs concurrently over HTTP and network/scheduler jitter
		// causes an older, shorter AppendEntries RPC (e.g. entries [1..2]) to arrive AFTER
		// a newer, longer AppendEntries RPC (e.g. entries [1..4]), this line silently
		// truncates entries [3..4] off the follower's log—even after the leader has marked
		// them replicated (`matchIndex = 4`) and committed them!
		n.log = append(n.log[:args.PrevLogIndex+1], args.Entries...)
	}

	if args.LeaderCommit > n.commitIndex {
		lastNewIdx := len(n.log) - 1
		if args.LeaderCommit < lastNewIdx {
			n.commitIndex = args.LeaderCommit
		} else {
			n.commitIndex = lastNewIdx
		}
		n.applyCommittedLocked()
	}

	reply.Success = true
	writeJSON(w, reply)
}

func (n *RaftNode) handlePropose(w http.ResponseWriter, r *http.Request) {
	var args ProposeArgs
	if err := json.NewDecoder(r.Body).Decode(&args); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	n.mu.Lock()
	if n.role != RoleLeader {
		leaderID := n.leaderID
		term := n.currentTerm
		n.mu.Unlock()
		writeJSON(w, ProposeReply{
			Success:  false,
			Term:     term,
			LeaderID: leaderID,
			Error:    "not leader",
		})
		return
	}

	entry := LogEntry{
		Index:   len(n.log),
		Term:    n.currentTerm,
		Command: args.Command,
	}
	n.log = append(n.log, entry)
	if n.verbose {
		fmt.Printf("[node %d] proposed index=%d term=%d cmd=%q\n", n.id, entry.Index, entry.Term, entry.Command)
	}

	// Immediately broadcast AppendEntries for low-latency replication.
	n.broadcastAppendEntriesLocked()
	n.mu.Unlock()

	writeJSON(w, ProposeReply{
		Success:  true,
		Index:    entry.Index,
		Term:     entry.Term,
		LeaderID: n.id,
	})
}

func (n *RaftNode) handleState(w http.ResponseWriter, r *http.Request) {
	n.mu.Lock()
	defer n.mu.Unlock()

	logCopy := make([]LogEntry, len(n.log))
	copy(logCopy, n.log)
	appliedCopy := make([]AppliedEntry, len(n.applied))
	copy(appliedCopy, n.applied)

	writeJSON(w, StateReply{
		ID:          n.id,
		Addr:        n.addr,
		Term:        n.currentTerm,
		Role:        n.role,
		VotedFor:    n.votedFor,
		CommitIndex: n.commitIndex,
		LastApplied: n.lastApplied,
		Log:         logCopy,
		Applied:     appliedCopy,
	})
}

func (n *RaftNode) postJSON(url string, reqBody any, respBody any) error {
	data, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}
	resp, err := n.httpClient.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status: %s", resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(respBody)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
