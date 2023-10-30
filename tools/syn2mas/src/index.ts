#!/usr/bin/env node
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

import log4js from "log4js";
import { ArgumentConfig, parse } from "ts-command-line-args";

import { advisor } from "./advisor.mjs";
import { migrate } from "./migrate.mjs";

log4js.configure({
  appenders: {
    console: { type: "console" },
  },
  categories: {
    default: { appenders: ["console"], level: "debug" },
  },
});

const log = log4js.getLogger();

interface MainOptions {
  command: string;
  help?: boolean;
}

const mainArgOptions: ArgumentConfig<MainOptions> = {
  command: {
    type: String,
    description: "Command to run",
    defaultOption: true,
    typeLabel: "<advisor|migrate>",
  },
  help: {
    type: Boolean,
    optional: true,
    alias: "h",
    description: "Prints this usage guide",
  },
};

export const mainArgs = parse<MainOptions>(mainArgOptions, {
  stopAtFirstUnknown: true,
});

try {
  if (mainArgs.command === "migrate") {
    await migrate();
    process.exit(0);
  }

  if (mainArgs.command === "advisor") {
    await advisor();
    process.exit(0);
  }

  parse<MainOptions>(mainArgOptions, { helpArg: "help" });
  process.exit(1);
} catch (e) {
  log.error(e);
  process.exit(1);
}
