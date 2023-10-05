import { ArgumentConfig, parse } from "ts-command-line-args";
import log4js from "log4js";

import { migrate } from "./migrate.mjs";
import { advisor } from "./advisor.mjs";

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
  command: { type: String, description: "Command to run", defaultOption: true, typeLabel: "<advisor|migrate>" },
  help: { type: Boolean, optional: true, alias: "h", description: "Prints this usage guide" },
};

export const mainArgs = parse<MainOptions>(mainArgOptions, { stopAtFirstUnknown: true });

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
