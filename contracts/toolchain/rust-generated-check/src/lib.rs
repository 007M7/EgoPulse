#![forbid(unsafe_code)]

pub mod egopulse {
    pub mod common {
        pub mod v1 {
            include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../generated/rust/egopulse.common.v1.rs"));
        }
    }
    pub mod task {
        pub mod v1 {
            include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../generated/rust/egopulse.task.v1.rs"));
        }
    }
    pub mod collaboration {
        pub mod v1 {
            include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../generated/rust/egopulse.collaboration.v1.rs"));
        }
    }
    pub mod harness {
        pub mod v1 {
            include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../generated/rust/egopulse.harness.v1.rs"));
        }
    }
    pub mod artifact {
        pub mod v1 {
            include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../generated/rust/egopulse.artifact.v1.rs"));
        }
    }
    pub mod verification {
        pub mod v1 {
            include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../generated/rust/egopulse.verification.v1.rs"));
        }
    }
    pub mod verdict {
        pub mod v1 {
            include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../generated/rust/egopulse.verdict.v1.rs"));
        }
    }
    pub mod policy {
        pub mod v1 {
            include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../generated/rust/egopulse.policy.v1.rs"));
        }
    }
    pub mod localapi {
        pub mod v1 {
            include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../generated/rust/egopulse.localapi.v1.rs"));
        }
    }
    pub mod persistence {
        pub mod v1 {
            include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../generated/rust/egopulse.persistence.v1.rs"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::egopulse::task::v1::TaskCommand;
    use prost::Message;

    #[test]
    fn generated_task_command_round_trips() {
        let command = TaskCommand::default();
        let encoded = command.encode_to_vec();
        let decoded = TaskCommand::decode(encoded.as_slice()).expect("generated protobuf decodes");
        assert_eq!(decoded.command, None);
    }
}
