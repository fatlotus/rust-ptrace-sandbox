use std::thread;

fn main() {
    for i in 0..100 {
        let handle = thread::spawn(move || {
            // Some work
            let mut sum = 0;
            for j in 0..1000 {
                sum += j;
            }
            if i % 10 == 0 {
                println!("Thread {} finished with sum {}", i, sum);
            }
        });
        handle.join().unwrap();
    }
    println!("Stress test finished!");
}
