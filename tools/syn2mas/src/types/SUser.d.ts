import { SynapseUserId, UnixTimestamp } from "./index";

export interface SUser {
  name: SynapseUserId; // '@test2:localhost:8008'
  password_hash?: string;
  admin: number;
  is_guest: number;
  deactivated: number;
  creation_ts: UnixTimestamp;
}
