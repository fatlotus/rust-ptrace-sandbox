# Raft over HTTP/REST — Finding & Reproducing a Subtle Logical Race

This directory contains a multi-node implementation of the [Raft consensus algorithm](https://raft.github.io/raft.pdf) in Go (`net/http` + JSON over loopback TCP), built to demonstrate how the `ptrace` deterministic sandbox can uncover and deterministically reproduce subtle distributed systems concurrency bugs.

---

## Overview

The application ([`raft.go`](./raft.go) and [`main.go`](./main.go)) starts an in-process 3-node Raft cluster where each node listens on an ephemeral `127.0.0.1` TCP port and communicates exclusively via HTTP REST endpoints:

- `POST /raft/request-vote` — Raft `RequestVote` RPC used during leader election
- `POST /raft/append-entries` — Raft `AppendEntries` RPC used for heartbeats and log replication
- `POST /raft/propose` — Client command submission (`{"command": "SET k=1"}`)
- `GET /raft/state` — Node state inspection (term, role, `commitIndex`, `lastApplied`, log entries, and applied state machine commands)

When [`main.go`](./main.go) runs, it:
1. Boots 3 Raft nodes (`node 0`, `node 1`, `node 2`) and waits for leader election to converge.
2. Submits 4 pipelined client proposals (`SET k=1` .. `SET k=4`) to the elected leader via `POST /raft/propose`.
3. Waits for replication and heartbeat settlement.
4. Queries every node via `GET /raft/state` and verifies core Raft safety invariants (**Election Safety**, **State Machine Safety**, **Log Matching**, and **Committed Log Convergence**).

---

## Building the Example

```bash
cd example
go build -o raft-example .
```

When run normally outside the sandbox—or inside the sandbox without jitter—RPCs over loopback arrive in order and the test passes every time:

```bash
# Run directly on the host
./raft-example

# Run in the deterministic sandbox with default settings (zero jitter)
cargo run -- ./example/raft-example
```

Output:
```text
Leader elected: node 2 (http://127.0.0.1:1026)

Cluster State Summary:
  node 0 (Follower  term=1 commit=4 applied=4): log=[1:SET k=1@t1, 2:SET k=2@t1, 3:SET k=3@t1, 4:SET k=4@t1] applied=[1:SET k=1, 2:SET k=2, 3:SET k=3, 4:SET k=4]
  node 1 (Follower  term=1 commit=4 applied=4): log=[1:SET k=1@t1, 2:SET k=2@t1, 3:SET k=3@t1, 4:SET k=4@t1] applied=[1:SET k=1, 2:SET k=2, 3:SET k=3, 4:SET k=4]
  node 2 (Leader    term=1 commit=4 applied=4): log=[1:SET k=1@t1, 2:SET k=2@t1, 3:SET k=3@t1, 4:SET k=4@t1] applied=[1:SET k=1, 2:SET k=2, 3:SET k=3, 4:SET k=4]

OK: All 4 proposals replicated, committed, and applied consistently across all 3 nodes.
```

---

## The Subtle Bug: Out-of-Order `AppendEntries` Log Truncation

A classic, real-world mistake when implementing Raft (highlighted in the [Students' Guide to Raft](https://thesquareplanet.com/blog/students-guide-to-raft/)) occurs in the `AppendEntries` RPC handler ([`handleAppendEntries`](./raft.go#L482-L502)):

```go
if len(args.Entries) > 0 {
    if args.PrevLogIndex >= len(n.log) || n.log[args.PrevLogIndex].Term != args.PrevLogTerm {
        writeJSON(w, reply)
        return
    }

    // BUG: Unconditionally slicing n.log[:args.PrevLogIndex+1] and appending args.Entries!
    n.log = append(n.log[:args.PrevLogIndex+1], args.Entries...)
}
```

### Why It Passes Normally
Under normal loopback execution without network jitter:
1. Proposals `SET k=1`, `SET k=2`, `SET k=3`, `SET k=4` arrive at the leader sequentially.
2. The leader sends `AppendEntries` RPC #1 (`entries=[1]`), RPC #2 (`entries=[1, 2]`), RPC #3 (`entries=[1, 2, 3]`), and RPC #4 (`entries=[1, 2, 3, 4]`).
3. When those HTTP requests are delivered in FIFO order across connections, each `AppendEntries` strictly extends the follower's log (`[1]` -> `[1, 2]` -> `[1, 2, 3]` -> `[1, 2, 3, 4]`).

### How the Logical Race Happens Under Jitter
When the leader pipelines multiple `AppendEntries` HTTP requests concurrently, each request uses its own TCP connection and goroutine. If network transit or epoll wakeup jitter causes **RPC #4 (`entries=[1..4]`) to be delivered to a follower before RPC #3 (`entries=[1..3]`)**:

1. **Follower receives RPC #4 (`PrevLogIndex=0, Entries=[1, 2, 3, 4]`)**:
   - The follower appends all 4 entries (`len(n.log) - 1 == 4`) and returns `Success: true`.
2. **Leader processes RPC #4's response**:
   - The leader updates `matchIndex[follower] = 4` and `nextIndex[follower] = 5`, advances `commitIndex = 4`, and applies all 4 commands to its state machine.
3. **Follower receives delayed RPC #3 (`PrevLogIndex=0, Entries=[1, 2, 3]`)**:
   - Because `args.Term == n.currentTerm` and `n.log[0].Term == args.PrevLogTerm`, the consistency check passes.
   - `n.log = append(n.log[:args.PrevLogIndex+1], args.Entries...)` **truncates entry 4 (`SET k=4`) off the follower's log**!
4. **Silent permanent divergence**:
   - Because the leader already recorded `nextIndex[follower] = 5`, subsequent leader heartbeats send `Entries: []` (`LeaderCommit: 4`), which never re-transmits entry 4. The follower's log and state machine remain permanently missing committed entry 4!

---

## Finding & Reproducing the Bug with the Sandbox

The `ptrace` sandbox supports two flags for deterministic fault/schedule exploration:
- `--seed <N>`: Seeds the sandbox's deterministic ChaCha12 PRNG, controlling `AT_RANDOM` (which seeds the Go runtime's internal `fastrand` scheduler/select tie-breaker and `math/rand`), `getrandom`, `/dev/urandom`, network transit delays, and timer jitter.
- `--jitter <duration>`: Enables deterministic virtual network transit jitter (up to `<duration>` per packet), `epoll_wait` ready-list shuffling, and sleep/timer jitter.

### 1. Fuzzing Seeds to Discover the Bug

Run a sweep across seeds `1..15` with `--jitter 15ms` from the repository root:

```bash
cargo build

for seed in $(seq 1 15); do
  if ./target/debug/ptrace --seed $seed --jitter 15ms ./example/raft-example >/dev/null 2>&1; then
    echo "seed $seed: PASS"
  else
    echo "seed $seed: FAIL (bug triggered!)"
  fi
done
```

Output:
```text
seed 1: PASS
seed 2: PASS
seed 3: PASS
seed 4: PASS
seed 5: PASS
seed 6: PASS
seed 7: PASS
seed 8: PASS
seed 9: PASS
seed 10: PASS
seed 11: PASS
seed 12: FAIL (bug triggered!)
seed 13: PASS
seed 14: PASS
seed 15: PASS
```

### 2. Deterministically Reproducing the Failure

Once a failing seed is found (such as `--seed 12 --jitter 15ms`), re-running with the same `--seed` and `--jitter` reproduces the exact same execution schedule, leader election, and log truncation failure every time:

```bash
./target/debug/ptrace --seed 12 --jitter 15ms ./example/raft-example
```

Output:
```text
Leader elected: node 2 (http://127.0.0.1:1026)

Cluster State Summary:
  node 0 (Follower  term=1 commit=3 applied=3): log=[1:SET k=1@t1, 2:SET k=2@t1, 3:SET k=3@t1] applied=[1:SET k=1, 2:SET k=2, 3:SET k=3]
  node 1 (Follower  term=1 commit=4 applied=4): log=[1:SET k=1@t1, 2:SET k=2@t1, 3:SET k=3@t1, 4:SET k=4@t1] applied=[1:SET k=1, 2:SET k=2, 3:SET k=3, 4:SET k=4]
  node 2 (Leader    term=1 commit=4 applied=4): log=[1:SET k=1@t1, 2:SET k=2@t1, 3:SET k=3@t1, 4:SET k=4@t1] applied=[1:SET k=1, 2:SET k=2, 3:SET k=3, 4:SET k=4]

INVARIANT VIOLATION (Committed Log Truncation Race): Leader node 2 committed 4 entries [1:SET k=1@t1, 2:SET k=2@t1, 3:SET k=3@t1, 4:SET k=4@t1], but follower node 0 has truncated log [1:SET k=1@t1, 2:SET k=2@t1, 3:SET k=3@t1] (commitIndex=3, lastApplied=3)!
  -> Cause: Out-of-order AppendEntries RPCs caused an older RPC with fewer entries to overwrite
     a newer RPC's entries on node 0 after the leader had already advanced matchIndex.
```

---

## How to Fix the Bug

To comply with Figure 2 of the Raft paper (AppendEntries receiver rules 3 & 4), `handleAppendEntries` in [`raft.go`](./raft.go) must iterate through `args.Entries` and only truncate `n.log` if an existing entry at the same index has a **conflicting term**, while preserving any existing suffix if the incoming `AppendEntries` is merely a shorter prefix from the same term:

```go
for i, entry := range args.Entries {
    idx := args.PrevLogIndex + 1 + i
    if idx < len(n.log) {
        if n.log[idx].Term != entry.Term {
            // Conflict detected: delete the existing entry and all that follow it
            n.log = n.log[:idx]
            n.log = append(n.log, args.Entries[i:]...)
            break
        }
        // Entry already matches at this index and term; keep scanning
    } else {
        // Append any new entries not already in the log
        n.log = append(n.log, args.Entries[i:]...)
        break
    }
}
```
