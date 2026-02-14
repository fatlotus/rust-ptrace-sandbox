use rand::RngCore;

fn main() {
    let mut rng = rand::thread_rng();
    let mut buf = [0u8; 16];
    rng.fill_bytes(&mut buf);
    println!("Random bytes: {:?}", buf);
}
