import { Id, SynapseUserId } from "./index";

/*
);
CREATE TABLE refresh_tokens (
    id bigint NOT NULL,
    user_id text NOT NULL,
    device_id text NOT NULL,
    token text NOT NULL,
    next_token_id bigint,
    expiry_ts bigint,
    ultimate_session_expiry_ts bigint
);
*/

export interface SRefreshToken {
  id: Id<SRefreshToken>;
  user_id: SynapseUserId;
  device_id: string;
  token: string;
  next_token_id?: number; // refresh or access?
  expiry_ts?: number;
  ultimate_session_expiry_ts?: number;
}
