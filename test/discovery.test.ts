import { describe, it, expect } from "vitest";

import {
  buildRecordName,
  postgresHostFromLeaderUrl,
} from "../src/discovery.js";

describe("buildRecordName", () => {
  it("prepends the leader label", () => {
    expect(buildRecordName("monitor.teesql.com")).toBe(
      "_teesql-leader.monitor.teesql.com"
    );
  });

  it("is idempotent when already prefixed", () => {
    const already = "_teesql-leader.monitor.teesql.com";
    expect(buildRecordName(already)).toBe(already);
  });
});

describe("postgresHostFromLeaderUrl", () => {
  it("defaults to 443 for https without an explicit port", () => {
    const { host, port } = postgresHostFromLeaderUrl(
      "https://ea23198e3419ebbb240571a29d0112d9bcbe69c0-5433.dstack-base-prod9.phala.network"
    );
    expect(host).toBe(
      "ea23198e3419ebbb240571a29d0112d9bcbe69c0-5433.dstack-base-prod9.phala.network"
    );
    expect(port).toBe(443);
  });

  it("respects an explicit port", () => {
    const { host, port } = postgresHostFromLeaderUrl("https://db.example.com:5432");
    expect(host).toBe("db.example.com");
    expect(port).toBe(5432);
  });

  it("defaults to 80 for http without an explicit port", () => {
    const { host, port } = postgresHostFromLeaderUrl("http://db.example.com");
    expect(host).toBe("db.example.com");
    expect(port).toBe(80);
  });
});
