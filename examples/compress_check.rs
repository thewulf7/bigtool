//! Re-compress real chunkzip payloads and report how close we get to EA's sizes.
use bigtool::big::Archive;
use bigtool::chunkzip;

fn main() {
    let path = std::env::args().nth(1).expect("usage: compress_check ARCHIVE [limit]");
    let limit: usize = std::env::args().nth(2).and_then(|s| s.parse().ok()).unwrap_or(usize::MAX);
    let arc = Archive::open(&path).expect("open");
    let (mut n, mut fail, mut bigger) = (0usize, 0usize, 0usize);
    let (mut ea_bytes, mut our_bytes, mut raw_bytes) = (0u64, 0u64, 0u64);
    let mut worst = 0.0f64;

    for r in arc.records() {
        if n >= limit {
            break;
        }
        let Ok(bytes) = arc.entry_bytes(r.position, false) else { continue };
        if !chunkzip::is_chunkzip(&bytes) {
            continue;
        }
        let plain = match chunkzip::decode(&bytes) {
            Ok(p) => p,
            Err(_) => {
                fail += 1;
                continue;
            }
        };
        n += 1;
        let enc = match chunkzip::encode(&plain) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("encode failed on {}: {e}", r.path);
                fail += 1;
                continue;
            }
        };
        match chunkzip::decode(&enc) {
            Ok(back) if back == plain => {}
            Ok(_) => {
                eprintln!("MISMATCH after re-encode: {}", r.path);
                fail += 1;
            }
            Err(e) => {
                eprintln!("cannot decode our own container ({}): {e}", r.path);
                fail += 1;
            }
        }
        ea_bytes += bytes.len() as u64;
        our_bytes += enc.len() as u64;
        raw_bytes += plain.len() as u64;
        if enc.len() > bytes.len() {
            bigger += 1;
        }
        let ratio = enc.len() as f64 / bytes.len() as f64;
        worst = worst.max(ratio);
    }

    println!("archive            : {path}");
    println!("containers tested  : {n}");
    println!("  raw (decompressed) : {:.2} MiB", raw_bytes as f64 / 1048576.0);
    println!("  EA compressed      : {:.2} MiB", ea_bytes as f64 / 1048576.0);
    println!("  ours               : {:.2} MiB  ({:.1}% of EA)", our_bytes as f64 / 1048576.0, 100.0 * our_bytes as f64 / ea_bytes.max(1) as f64);
    println!("  round-trip failures: {fail}");
    println!("  larger than EA     : {bigger} (worst container {:.2}x EA)", worst);
}
