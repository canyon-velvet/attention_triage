import { render, screen } from "@testing-library/react";
import { expect, test } from "vitest";
import { FlagItem } from "./FlagItem";
import { flag } from "./testing";

test("a flag item shows what ran, why, the rule and where", () => {
  render(<FlagItem flag={flag} />);
  expect(screen.getByText("rm -rf build")).toBeInTheDocument();
  expect(screen.getByText("Bash")).toBeInTheDocument();
  expect(screen.getByText("Clean the build folder")).toBeInTheDocument();
  expect(screen.getByText("sandbox_bypass")).toBeInTheDocument();
  expect(screen.getByText("high")).toBeInTheDocument();
  expect(screen.getByText("preemptive")).toBeInTheDocument();
  expect(screen.getByText("command: rm -rf build")).toBeInTheDocument();
  expect(screen.getByText("/p/main/.claude/worktrees/wt")).toBeInTheDocument();
  expect(screen.getByRole("time")).toHaveAttribute("datetime", flag.time);
});

test("a flag without a label shows no empty label tag", () => {
  const { container } = render(<FlagItem flag={{ ...flag, label: "" }} />);
  expect(container.querySelector(".label")).toBeNull();
});

test("a partial flag says shell network access is not fully visible", () => {
  render(<FlagItem flag={{ ...flag, label: "partial" }} />);
  expect(screen.getByText(/shell network access is not fully visible/i)).toBeInTheDocument();
});

test("other flags carry no visibility caveat", () => {
  render(<FlagItem flag={flag} />);
  expect(screen.queryByText(/not fully visible/i)).toBeNull();
});

test("captured commands render as text, never as HTML", () => {
  const html = '<img src=x onerror="alert(1)">';
  const { container } = render(
    <FlagItem flag={{ ...flag, target: html, stated_reason: html, evidence: { command: html } }} />,
  );
  expect(container.querySelector("img")).toBeNull();
  expect(screen.getAllByText(html, { exact: false })).toHaveLength(3);
});
