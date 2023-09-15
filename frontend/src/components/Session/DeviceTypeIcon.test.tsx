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

import { DeviceType } from "../../utils/parseUserAgent";

import DeviceTypeIcon from "./DeviceTypeIcon";

describe("<DeviceTypeIcon />", () => {
  afterEach(cleanup);

  it("renders unknown device type", () => {
    const { container } = render(
      <DeviceTypeIcon deviceType={DeviceType.Unknown} />,
    );
    expect(container).toMatchSnapshot();
  });
  it("renders mobile device type", () => {
    const { container } = render(
      <DeviceTypeIcon deviceType={DeviceType.Mobile} />,
    );
    expect(container).toMatchSnapshot();
  });
  it("renders desktop device type", () => {
    const { container } = render(
      <DeviceTypeIcon deviceType={DeviceType.Desktop} />,
    );
    expect(container).toMatchSnapshot();
  });
  it("renders Web device type", () => {
    const { container } = render(
      <DeviceTypeIcon deviceType={DeviceType.Web} />,
    );
    expect(container).toMatchSnapshot();
  });
});
