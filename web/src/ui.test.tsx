import { render, screen } from "@testing-library/react";
import { Metric, OkPill, Pill, fmt, bytes } from "./ui";

describe("status pills", () => {
  it("always carry a word, not only a colour", () => {
    render(<OkPill ok={false} yes="valid" no="Signature invalid" />);
    expect(screen.getByText("Signature invalid")).toBeTruthy();
  });
  it("show skipped for unknown results", () => {
    render(<OkPill ok={null} yes="a" no="b" />);
    expect(screen.getByText("skipped")).toBeTruthy();
  });
  it("render the tone class", () => {
    const { container } = render(<Pill tone="pass">ok</Pill>);
    expect(container.querySelector(".pill.pass")).toBeTruthy();
  });
});

describe("metric card", () => {
  it("shows value, unit and an ideal marker", () => {
    const { container } = render(<Metric label="NPCR" value="99.6" unit="%" pct={99.6} ideal={99.61} />);
    expect(screen.getByText("NPCR")).toBeTruthy();
    expect(container.querySelector(".meter > i")).toBeTruthy();
  });
});

describe("formatting", () => {
  it("formats numbers, infinity and sizes", () => {
    expect(fmt("inf")).toBe("∞");
    expect(fmt(null)).toBe("–");
    expect(fmt(0.00001)).toBe("1.00e-5");
    expect(bytes(2048)).toBe("2 KB");
  });
});
