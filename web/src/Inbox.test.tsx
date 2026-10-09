import { render, screen } from "@testing-library/react";
import { expect, test, vi } from "vitest";
import type { Digest } from "./api";
import { Inbox } from "./Inbox";
import { flag } from "./testing";

function serve(digest: Digest | null) {
  const response = digest ? { ok: true, json: async () => digest } : { ok: false, status: 500 };
  vi.stubGlobal("fetch", vi.fn(async () => response));
}

test("the inbox shows the headline and flags grouped by project and session", async () => {
  serve({
    headline: { actions: 214, captured: 214, need_review: 1 },
    projects: [{ project: "/p/main", sessions: [{ session_id: "73eb2355-abcd", flags: [flag] }] }],
  });
  render(<Inbox />);
  expect(await screen.findByText("214 actions · 214 captured · 1 need review")).toBeInTheDocument();
  expect(screen.getByRole("heading", { name: "/p/main" })).toBeInTheDocument();
  expect(screen.getByRole("heading", { name: "Session 73eb2355" })).toBeInTheDocument();
  expect(screen.getByText("rm -rf build")).toBeInTheDocument();
});

test("the inbox says when nothing needs review", async () => {
  serve({ headline: { actions: 3, captured: 3, need_review: 0 }, projects: [] });
  render(<Inbox />);
  expect(await screen.findByText("Nothing needs review.")).toBeInTheDocument();
});

test("the inbox says when the digest can't be loaded", async () => {
  serve(null);
  render(<Inbox />);
  expect(await screen.findByText("Couldn't load the digest: HTTP 500")).toBeInTheDocument();
});
