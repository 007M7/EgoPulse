#![forbid(unsafe_code)]

use prost::Message;
use prost_types::FileDescriptorSet;
use std::env;
use std::fs;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args_os().skip(1);
    let descriptor_path = PathBuf::from(
        arguments
            .next()
            .ok_or("usage: egopulse-contract-rust-codegen <descriptor-set> <output-dir>")?,
    );
    let output_directory = PathBuf::from(
        arguments
            .next()
            .ok_or("usage: egopulse-contract-rust-codegen <descriptor-set> <output-dir>")?,
    );
    if arguments.next().is_some() {
        return Err("unexpected extra codegen argument".into());
    }

    let descriptor_bytes = fs::read(&descriptor_path)?;
    let descriptor_set = FileDescriptorSet::decode(descriptor_bytes.as_slice())?;
    fs::create_dir_all(&output_directory)?;

    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .build_transport(true)
        // Prost does not infer Eq/Hash through a repeated message field. All
        // approval-display members are discrete values; derive these traits
        // explicitly so adding the summary preserves the existing Rust
        // observation API. Rust verifies the member bounds when compiling.
        .message_attribute(
            ".egopulse.harness.v1.ApprovalDisplaySummary",
            "#[derive(Eq, Hash)]",
        )
        .message_attribute(
            ".egopulse.harness.v1.ApprovalRequestObservation",
            "#[derive(Eq, Hash)]",
        )
        .message_attribute(
            ".egopulse.harness.v1.HarnessObservation",
            "#[derive(Eq, Hash)]",
        )
        .enum_attribute(
            ".egopulse.harness.v1.HarnessObservation.payload",
            "#[derive(Eq, Hash)]",
        )
        .out_dir(output_directory)
        .compile_fds(descriptor_set)?;

    Ok(())
}
