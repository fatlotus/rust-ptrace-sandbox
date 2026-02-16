use std::thread;

fn main() {
    let handle = thread::spawn(|| {
        println!("Hello from thread!");
    });
    handle.join().unwrap();
    println!("Thread joined!");
}
