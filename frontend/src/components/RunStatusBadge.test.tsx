import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { RunStatusBadge } from "./RunStatusBadge";

describe("RunStatusBadge", () => {
  it.each([
    ["running", "Running"],
    ["cancelled", "Cancelled"],
    ["failed", "Failed"],
  ])("renders %s", (status, text) => {
    render(<RunStatusBadge status={status} />);
    expect(screen.getByText(text)).toBeTruthy();
  });

  it("is only green-free: a cancelled or failed run never looks successful", () => {
    for (const status of ["running", "cancelled", "failed"]) {
      const { container, unmount } = render(<RunStatusBadge status={status} />);
      expect(container.innerHTML).not.toContain("rh-go");
      unmount();
    }
  });

  it.each([["completed"], [undefined], [null], [""], ["weird"]])("renders nothing for %s", (status) => {
    const { container } = render(<RunStatusBadge status={status as string | null | undefined} />);
    expect(container.innerHTML).toBe("");
  });
});
