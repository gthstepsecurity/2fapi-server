// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
//! Redis module infrastructure layer.
//!
//! Implements Redis commands for 2FApi ZKP authentication:
//!   Core: ENROLL, CHALLENGE, VERIFY, STATUS, SUSPEND, REVOKE, INFO, WHOAMI
//!   Device Linking: LINK_REQUEST, LINK_SET_HASH, LINK_VERIFY, LINK_CONFIRM,
//!                   DEVICE_ENROLL, DEVICE_LIST, DEVICE_REVOKE

pub mod commands;
pub mod device_commands;
pub mod session;
