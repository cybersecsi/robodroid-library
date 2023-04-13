import type { RoboDroidBehaviorStatus, LogLevel } from '@robodroid/utils/types'

export interface IRoboDroidMessage {
  msg: string;
  status: RoboDroidBehaviorStatus;
  outputs?: any
}

export interface IRoboDroidLogger {
  logLevel: LogLevel;
  setLogLevel: (logLevel: LogLevel) => void;
  log: (msg: string) => void;
  debug: (msg: string) => void;
}

export interface IAndroidFilesystem {
  files: any;
  path: string;
  readable: boolean;
  writable: boolean;
}

export interface IExecutedCommand {
  command: string;
  stdOut: string;
  stdErr: string;
}

export interface ICurrentActivityFragment {
  activity: string | null;
  fragment: string | null;
}

export interface IJavaField {
  name: string;
  value: string;
}