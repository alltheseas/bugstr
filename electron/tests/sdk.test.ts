import { describe, expect, it, vi, beforeEach } from "vitest";
import { init, captureException } from "../src/sdk.ts";

describe("Bugstr SDK (unit)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("drops errors when not initialized", () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    captureException(new Error("boom"));
    expect(warnSpy).toHaveBeenCalledWith("Bugstr not initialized; dropping error");
  });

  it("redacts secrets and prompts before send", async () => {
    const confirmSpy = vi.fn().mockReturnValue(true);
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const logSpy = vi.spyOn(console, "info").mockImplementation(() => {});

    // Stub sendToNostr via beforeSend cancel to avoid network and focus on payload/redaction
    init({
      developerPubkey: "6d8ee5c3ac046058ee6cfeb9edc637ce6a4375d0b24dc29490e1fe401d80851a",
      relays: ["wss://relay.damus.io"],
      environment: "test",
      release: "test",
      confirmSend: (summary) => {
        expect(summary.message).toContain("[redacted]");
        confirmSpy();
        return true;
      },
      beforeSend: (payload) => {
        expect(payload.message).toContain("[redacted]");
        expect(payload.stack).toContain("[redacted]");
        return null; // cancel send
      },
    });

    captureException(new Error("cashuA123 npub1abc lnbc1xyz"));
    expect(confirmSpy).toHaveBeenCalled();
    expect(warnSpy).not.toHaveBeenCalledWith(expect.stringContaining("dropping error"));

    logSpy.mockRestore();
    confirmSpy.mockRestore();
    warnSpy.mockRestore();
  });
});
