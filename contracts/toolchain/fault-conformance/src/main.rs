#![forbid(unsafe_code)]

use egopulse_v01_fault_conformance::inject_and_abort;
use std::path::Path;

fn main() {
    let mut args = std::env::args().skip(1);
    let boundary = args.next().expect("boundary argument");
    let root = args.next().expect("run root argument");
    inject_and_abort(&boundary, Path::new(&root)).expect("fault injection setup");
    panic!("fault injector returned without aborting");
}
