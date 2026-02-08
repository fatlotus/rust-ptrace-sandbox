use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

fn main() {
    // 1. Bind an acceptor socket on some arbitrary port.
    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind");
    let addr = listener.local_addr().expect("Failed to get local addr");
    println!("Bound to {}", addr);

    // 2. (In a separate thread) Accept on the socket once, then close the socket and exit.
    let handle = thread::spawn(move || {
        let (mut stream, _addr) = listener.accept().expect("Failed to accept");
        println!("Accepted connection");
        
        let mut buf = [0; 128];
        let n = stream.read(&mut buf).expect("Failed to read");
        stream.write_all(&buf[..n]).expect("Failed to write");
    });

    // 3. Connect to the server socket. After it connects, close and exit.
    let mut stream = TcpStream::connect(addr).expect("Failed to connect");
    println!("Connected to {}", addr);
    
    stream.write_all(b"hello").expect("Failed to write to server");
    
    let mut buf = [0; 128];
    let n = stream.read(&mut buf).expect("Failed to read from server");
    assert_eq!(&buf[..n], b"hello");

    handle.join().expect("Thread panicked");
    println!("Done");
}
