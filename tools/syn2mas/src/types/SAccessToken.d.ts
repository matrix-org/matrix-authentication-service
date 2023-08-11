import { Id, SynapseUserId } from "./index";
import { SRefreshToken } from "./SRefreshToken";

/*
CREATE TABLE access_tokens (
    id bigint NOT NULL,
    user_id text NOT NULL,
    device_id text,
    token text NOT NULL,
    valid_until_ms bigint,
    puppets_user_id text,
    last_validated bigint,
    refresh_token_id bigint,
    used boolean
);
*/
export interface SAccessToken {
  id: Id<SAccessToken>;
  user_id: SynapseUserId;
  device_id?: string;
  token: string;
  valid_until_ms?: number;
  puppets_user_id?: SynapseUserId;
  last_validated?: number;
  refresh_token_id?: Id<SRefreshToken>;
  used: boolean;
}
