use serde::Deserialize;
use std::fs;

#[derive(Deserialize)]
struct User {
    name: String,
    age: u8,
}

fn main() {
    let data = fs::read_to_string("user.json").unwrap();
    let user: User = serde_json::from_str(&data).unwrap();
    println!("{}", user.name);
}
