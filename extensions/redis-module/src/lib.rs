// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
//! redis-2fapi — Zero-Knowledge Proof authentication module for Redis
//!
//! Commands:
//!   Core auth:      ENROLL, CHALLENGE, VERIFY, STATUS, SUSPEND, REVOKE, INFO, WHOAMI
//!   Device linking: LINK_REQUEST, LINK_SET_HASH, LINK_VERIFY, LINK_CONFIRM,
//!                   DEVICE_ENROLL, DEVICE_LIST, DEVICE_REVOKE

pub mod domain;

#[cfg(feature = "redis-module")]
pub mod infrastructure;

#[cfg(feature = "redis-module")]
redis_module::redis_module! {
    name: "2fapi",
    version: 1,
    allocator: (redis_module::alloc::RedisAlloc, redis_module::alloc::RedisAlloc),
    data_types: [],
    commands: [
        // Core authentication
        ["2FAPI.ENROLL", infrastructure::commands::cmd_enroll, "write deny-oom", 0, 0, 0],
        ["2FAPI.CHALLENGE", infrastructure::commands::cmd_challenge, "write deny-oom", 0, 0, 0],
        ["2FAPI.VERIFY", infrastructure::commands::cmd_verify, "write deny-oom", 0, 0, 0],
        ["2FAPI.STATUS", infrastructure::commands::cmd_status, "readonly", 0, 0, 0],
        ["2FAPI.SUSPEND", infrastructure::commands::cmd_suspend, "write", 0, 0, 0],
        ["2FAPI.REVOKE", infrastructure::commands::cmd_revoke, "write", 0, 0, 0],
        ["2FAPI.INFO", infrastructure::commands::cmd_info, "readonly", 0, 0, 0],
        ["2FAPI.WHOAMI", infrastructure::commands::cmd_whoami, "readonly fast", 0, 0, 0],
        // Device linking
        ["2FAPI.LINK_REQUEST", infrastructure::device_commands::cmd_link_request, "write deny-oom", 0, 0, 0],
        ["2FAPI.LINK_SET_HASH", infrastructure::device_commands::cmd_link_set_hash, "write", 0, 0, 0],
        ["2FAPI.LINK_VERIFY", infrastructure::device_commands::cmd_link_verify, "write", 0, 0, 0],
        ["2FAPI.LINK_CONFIRM", infrastructure::device_commands::cmd_link_confirm, "write", 0, 0, 0],
        ["2FAPI.DEVICE_ENROLL", infrastructure::device_commands::cmd_device_enroll, "write deny-oom", 0, 0, 0],
        ["2FAPI.DEVICE_LIST", infrastructure::device_commands::cmd_device_list, "readonly", 0, 0, 0],
        ["2FAPI.DEVICE_REVOKE", infrastructure::device_commands::cmd_device_revoke, "write", 0, 0, 0],
    ],
}
