// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type {
  EnrollDevice,
  EnrollDeviceInput,
  EnrollDeviceResult,
} from "../../domain/port/incoming/enroll-device.js";
import type { EnrollmentTokenStore } from "../../domain/port/outgoing/enrollment-token-store.js";
import type { DeviceRegistrationStore } from "../../domain/port/outgoing/device-registration-store.js";
import { DeviceRegistration } from "../../domain/model/device-registration.js";

interface Dependencies {
  readonly enrollmentTokenStore: EnrollmentTokenStore;
  readonly deviceRegistrationStore: DeviceRegistrationStore;
  readonly validateCommitment: (commitmentHex: string) => boolean;
  readonly nowMs: () => number;
  readonly generateDeviceId: () => string;
}

export class EnrollDeviceUseCase implements EnrollDevice {
  constructor(private readonly deps: Dependencies) {}

  async execute(input: EnrollDeviceInput): Promise<EnrollDeviceResult> {
    // FIX RT-DL-06: atomic consume prevents TOCTOU race.
    // Before: findByValue → check consumed → save(consumed=true) — two concurrent
    // requests both pass the check and both consume the token.
    // After: atomicConsume does UPDATE ... WHERE consumed=false in one DB round-trip.
    const token = await this.deps.enrollmentTokenStore.atomicConsume(input.enrollmentToken);
    if (!token) {
      return { status: "invalid_token" };
    }

    if (token.isExpired(this.deps.nowMs())) {
      return { status: "token_expired" };
    }

    if (!this.deps.validateCommitment(input.commitmentHex)) {
      return { status: "invalid_commitment" };
    }

    const deviceId = this.deps.generateDeviceId();
    const registration = DeviceRegistration.create({
      clientId: token.clientId,
      deviceId,
      deviceName: input.deviceName,
      enrolledAt: this.deps.nowMs(),
      commitmentHex: input.commitmentHex,
    });
    await this.deps.deviceRegistrationStore.save(registration);

    return { status: "enrolled", deviceId };
  }
}
