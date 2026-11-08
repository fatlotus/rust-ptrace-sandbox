# Raft over HTTP/REST: Finding and Reproducing a Log Truncation Race

This directory contains a 3-node [Raft](https://raft.github.io/raft.pdf) cluster written in Go (`net/http` + JSON over loopback TCP). It demonstrates how `nodice` finds and reproduces a race condition in concurrent network code.

## Overview

The program ([`raft.go`](./raft.go) and [`main.go`](./main.go)) starts three Raft nodes in a single process. Each node listens on an ephemeral `127.0.0.1` TCP port and communicates over HTTP:

- `POST /raft/request-vote`: `RequestVote` RPC used during leader election
- `POST /raft/append-entries`: `AppendEntries` RPC used for heartbeats and log replication
- `POST /raft/propose`: Client command submission (`{"command": "SET k=1"}`)
- `GET /raft/state`: Node state inspection (term, role, `commitIndex`, `lastApplied`, log entries, and applied commands)

When [`main.go`](./main.go) runs, it:
1. Starts `node 0`, `node 1`, and `node 2`, and waits for them to elect a leader.
2. Sends four pipelined client proposals (`SET k=1` .. `SET k=4`) to the leader.
3. Waits briefly for replication and heartbeats to settle.
4. Queries all three nodes and checks that committed entries are present and applied everywhere.

## Building and Running

Build the example binary:

```bash
cd example
go build -o raft-example .
cd ..
```

When run directly on the host, or under `nodice` with zero jitter, loopback RPCs arrive in FIFO order and the check passes:

```bash
# Run directly on the host
./example/raft-example

# Run under nodice with default settings (zero jitter)
nodice ./example/raft-example
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

## The Bug: Out-of-Order `AppendEntries` Log Truncation

A common mistake when implementing Raft (described in the [Students' Guide to Raft](https://thesquareplanet.com/blog/students-guide-to-raft/)) is in [`handleAppendEntries`](./raft.go#L482-L502):

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

When the leader pipelines `AppendEntries` requests concurrently over separate HTTP connections, network jitter can deliver **RPC #4 (`entries=[1..4]`)** to a follower before **RPC #3 (`entries=[1..3]`)**:

1. The follower receives RPC #4 first, appends entries `1..4`, and replies `Success: true`.
2. The leader records `matchIndex = 4` and `nextIndex = 5` for that follower, advances `commitIndex = 4`, and applies all four commands.
3. The delayed RPC #3 arrives at the follower. Its `PrevLogIndex` and `PrevLogTerm` are still valid, so `n.log = append(n.log[:args.PrevLogIndex+1], args.Entries...)` overwrites the log with `entries=[1..3]`, truncating committed entry 4.
4. Because the leader already advanced `nextIndex = 5`, subsequent heartbeats send empty `Entries: []` and never re-send entry 4.

## Finding and Reproducing the Bug with `nodice`

### 1. Search Across Iterations

Instead of writing a shell loop, pass `--iterations` to `nodice`. It runs the test in parallel across all CPU cores, hides the output from successful runs, and increases the jitter from `1ms` upward until an iteration fails:

```bash
nodice --iterations 15 ./example/raft-example
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

Failed on iteration 3/15 (seed 3, jitter 3ms). Reproduce with:
  nodice --seed 3 --jitter 3ms ./example/raft-example
```

### 2. Replay the Failing Run

Run the printed reproduction command to replay that exact failure:

```bash
nodice --seed 3 --jitter 3ms ./example/raft-example
```

Every run with `--seed 3 --jitter 3ms` elects the same leader, delivers the RPCs in the same order, and triggers the same truncation on `node 0`.

## Fixing the Bug

Following Figure 2 of the Raft paper (`AppendEntries` receiver rules 3 and 4), [`handleAppendEntries`](./raft.go) should only truncate the log when an existing entry at the same index has a conflicting term:

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
