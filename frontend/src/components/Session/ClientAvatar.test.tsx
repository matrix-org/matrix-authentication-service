// Copyright 2023 The Matrix.org Foundation C.I.C.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// @vitest-environment happy-dom

import { render, cleanup } from "@testing-library/react";
import { describe, it, expect, afterEach } from "vitest";

import ClientAvatar from "./ClientAvatar";

describe("<ClientAvatar />", () => {
  const name = "Test Client";
  const logoUri = "https://www.testclient.com/logo.png";
  const size = "10px";

  afterEach(cleanup);

  it("renders client logo", () => {
    const { container } = render(
      <ClientAvatar name={name} logoUri={logoUri} size={size} />,
    );
    expect(container).toMatchSnapshot();
  });

  it("renders nothing when no logoUri is falsy", () => {
    const { container } = render(<ClientAvatar name={name} size={size} />);
    expect(container).toMatchInlineSnapshot("<div />");
  });
});
