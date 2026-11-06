import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { VerdictBadge } from "./VerdictBadge";

describe("VerdictBadge", () => {
  it.each([
    ["GO", "GO"],
    ["CONDITIONAL_GO", "Conditional go"],
    ["NO_GO", "No go"],
    ["SCANNED", "Scanned"],
  ])("renders %s", (verdict, text) => {
    render(<VerdictBadge verdict={verdict} />);
    expect(screen.getByText(text)).toBeTruthy();
  });

  it.each([[null], [undefined], [""]])("renders Not evaluated for %s", (v) => {
    render(<VerdictBadge verdict={v} />);
    expect(screen.getByText("Not evaluated")).toBeTruthy();
  });

  it("never renders an unknown verdict as green", () => {
    const { container } = render(<VerdictBadge verdict="PASS" />);
    expect(container.innerHTML).not.toContain("rh-go");
    expect(screen.getByText("PASS")).toBeTruthy();
  });

  it("only GO is green", () => {
    const { container } = render(<VerdictBadge verdict="GO" />);
    expect(container.innerHTML).toContain("rh-go");
  });

  it("renders NOT_EVALUATED as a neutral 'Not evaluated', never red or green", () => {
    const { container } = render(<VerdictBadge verdict="NOT_EVALUATED" />);
    expect(screen.getByText("Not evaluated")).toBeTruthy();
    expect(screen.queryByText(/NOT EVALUATED/)).toBeNull();
    expect(container.innerHTML).toContain("text-rh-muted");
    expect(container.innerHTML).not.toContain("rh-nogo");
    expect(container.innerHTML).not.toContain("rh-go");
    expect(container.innerHTML).not.toContain("No go");
  });
});
