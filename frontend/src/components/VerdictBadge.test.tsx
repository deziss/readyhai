import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { VerdictBadge } from "./VerdictBadge";

describe("VerdictBadge", () => {
  it.each([
    ["GO", "GO"],
    ["CONDITIONAL_GO", "CONDITIONAL GO"],
    ["NO_GO", "NO GO"],
    ["SCANNED", "SCANNED"],
  ])("renders %s", (verdict, text) => {
    render(<VerdictBadge verdict={verdict} />);
    expect(screen.getByText(text)).toBeTruthy();
  });

  it.each([[null], [undefined], [""]])("renders NOT EVALUATED for %s", (v) => {
    render(<VerdictBadge verdict={v} />);
    expect(screen.getByText("NOT EVALUATED")).toBeTruthy();
  });

  it("never renders an unknown verdict as green", () => {
    const { container } = render(<VerdictBadge verdict="PASS" />);
    expect(container.innerHTML).not.toContain("emerald");
    expect(screen.getByText("PASS")).toBeTruthy();
  });

  it("only GO is green", () => {
    const { container } = render(<VerdictBadge verdict="GO" />);
    expect(container.innerHTML).toContain("emerald");
  });
});
