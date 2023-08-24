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

import { create } from "react-test-renderer";
import { describe, expect, it, vi, afterAll } from "vitest";

import Layout from "./Layout";

const RESULT = Symbol("Result");
const OK = Symbol("Ok");

vi.mock("jotai", async () => {
  const actual = await vi.importActual("jotai");
  return {
    ...(actual as Record<string, unknown>),
    useAtomValue: vi
      .fn()
      .mockImplementation(() => ({ [RESULT]: OK, [OK]: null })),
  };
});

describe("<Layout />", () => {
  afterAll(() => {
    vi.restoreAllMocks();
  });
  it("renders an active session", () => {
    const component = create(<Layout />);

    expect(component.toJSON()).toMatchSnapshot();
  });
});
