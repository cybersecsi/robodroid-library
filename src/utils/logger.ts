import { LogLevel } from "@robodroid/utils/types";
import { IRoboDroidLogger } from "./interfaces";

export const logger: IRoboDroidLogger = {
  logLevel: "normal",
  setLogLevel(logLevel: LogLevel) {
    this.logLevel = logLevel;
  },
  log(msg: string) {
    if (this.logLevel !== "silent") {
      const now = new Date();
      const timestamp = now.toTimeString().substring(0,8);
      console.log(`\x1B[35m[${timestamp}] - [FRIDA] - ${msg}\x1b[39m`);
    }
  },
  debug(msg: string) {
    if (this.logLevel === "verbose") {
      const now = new Date();
      const timestamp = now.toTimeString().substring(0,8);
      console.log(`\x1B[35m[${timestamp}] - [FRIDA] - ${msg}\x1b[39m`);
    }
  }
}