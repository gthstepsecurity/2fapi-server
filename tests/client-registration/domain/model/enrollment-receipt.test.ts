// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { EnrollmentReceipt } from "../../../../src/client-registration/domain/model/enrollment-receipt.js";

describe("EnrollmentReceipt", () => {
  it("holds referenceId and clientIdentifier", () => {
    const receipt = new EnrollmentReceipt("ref-123", "client-abc");
    expect(receipt.referenceId).toBe("ref-123");
    expect(receipt.clientIdentifier).toBe("client-abc");
  });

  it("equals another receipt with same values", () => {
    const a = new EnrollmentReceipt("ref-1", "client-1");
    const b = new EnrollmentReceipt("ref-1", "client-1");
    expect(a.equals(b)).toBe(true);
  });

  it("does not equal a receipt with different referenceId", () => {
    const a = new EnrollmentReceipt("ref-1", "client-1");
    const b = new EnrollmentReceipt("ref-2", "client-1");
    expect(a.equals(b)).toBe(false);
  });

  it("does not equal a receipt with different clientIdentifier", () => {
    const a = new EnrollmentReceipt("ref-1", "client-1");
    const b = new EnrollmentReceipt("ref-1", "client-2");
    expect(a.equals(b)).toBe(false);
  });

  it("does not equal a receipt with both values different", () => {
    const a = new EnrollmentReceipt("ref-1", "client-1");
    const b = new EnrollmentReceipt("ref-2", "client-2");
    expect(a.equals(b)).toBe(false);
  });
});
