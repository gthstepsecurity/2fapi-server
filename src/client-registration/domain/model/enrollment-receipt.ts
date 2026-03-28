// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
export class EnrollmentReceipt {
  constructor(
    readonly referenceId: string,
    readonly clientIdentifier: string,
  ) {}

  equals(other: EnrollmentReceipt): boolean {
    return (
      this.referenceId === other.referenceId &&
      this.clientIdentifier === other.clientIdentifier
    );
  }
}
