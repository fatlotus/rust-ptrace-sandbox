use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

fn main() {
    let order = Arc::new(Mutex::new(Vec::new()));

    // Spawn 3 threads with different sleep durations
    // Thread 1 sleeps for 2 seconds
    let order1 = order.clone();
    let h1 = thread::spawn(move || {
        println!("Hello from thread 1 (sleep 2s)!");
        thread::sleep(Duration::from_secs(2));
        order1.lock().unwrap().push(1);
    });

    // Thread 2 sleeps for 1 second
    let order2 = order.clone();
    let h2 = thread::spawn(move || {
        println!("Hello from thread 2 (sleep 1s)!");
        thread::sleep(Duration::from_secs(1));
        order2.lock().unwrap().push(2);
    });

    // Thread 3 sleeps for 3 seconds
    let order3 = order.clone();
    let h3 = thread::spawn(move || {
        println!("Hello from thread 3 (sleep 3s)!");
        thread::sleep(Duration::from_secs(3));
        order3.lock().unwrap().push(3);
    });

    println!("Hello from thread!");

    h2.join().unwrap();
    h1.join().unwrap();
    h3.join().unwrap();

    let final_order = order.lock().unwrap().clone();
    println!("Wake order: {:?}", final_order);
    assert_eq!(final_order, vec![2, 1, 3], "Threads must wake in priority queue order (1s, 2s, 3s)");

    println!("Thread joined!");
    println!("Multi-thread sleep simulation verified!");
}
