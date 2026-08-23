use egopulse_v01_fault_conformance::{recover_and_verify, BOUNDARIES};
use std::path::PathBuf;
use std::process::Command;

#[test]
fn seven_durable_boundaries_survive_ten_real_process_aborts_each() {
    let binary = env!("CARGO_BIN_EXE_egopulse-v01-fault-conformance");
    let run_base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target").join("fault-runs");
    for boundary in BOUNDARIES {
        for iteration in 0..10 {
            let root = run_base.join(format!("{boundary}-{iteration}"));
            if root.exists() {
                std::fs::remove_dir_all(&root).expect("remove prior isolated test run");
            }
            let status = Command::new(binary)
                .arg(boundary)
                .arg(&root)
                .status()
                .expect("launch fault injector");
            assert!(!status.success(), "{boundary} iteration {iteration} must terminate abruptly");
            recover_and_verify(boundary, &root)
                .unwrap_or_else(|error| panic!("{boundary} iteration {iteration} recovery failed: {error}"));
            std::fs::remove_dir_all(&root).expect("remove completed isolated test run");
        }
        println!("fault_boundary={boundary} injections=10 recovery=passed");
    }
}
