// No explicit Patina init/shutdown: the packaged startup path installs and
// finalizes the runtime around ordinary application code. HashMap iteration
// order is observed by collecting the keys in iteration order; std's RandomState
// seeds its hasher from the (Patina-seeded) entropy source.
use std::collections::HashMap;

fn main() {
    let mut map = HashMap::new();
    for i in 0..16u32 {
        map.insert(format!("key-{i}"), i);
    }
    let order: Vec<String> = map.keys().cloned().collect();
    println!("NATIVE_HASHMAP_ORDER {}", order.join(","));
}
