use std::thread;
use std::time::{Duration, Instant};

fn main() {
    let start = Instant::now();
    println!("Sleeping for 10 seconds...");
    thread::sleep(Duration::from_secs(10));
    let elapsed = start.elapsed();
    println!("Virtual elapsed: {:?}", elapsed);
    assert!(elapsed >= Duration::from_secs(10), "Virtual elapsed time must be >= 10s");
    println!("Sleep completed successfully!");
}
