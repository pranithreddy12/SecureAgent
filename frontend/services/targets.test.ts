import { describe, expect, it } from "vitest";

import { parseHeaderLines } from "./targets";

describe("parseHeaderLines", () => {
  it("splits on the first colon and ignores blank or malformed lines", () => {
    expect(parseHeaderLines("Cookie: a=1; b=2\r\n\nAuthorization: Bearer x:y\nnonsense")).toEqual({
      Cookie: "a=1; b=2",
      Authorization: "Bearer x:y",
    });
  });
});
