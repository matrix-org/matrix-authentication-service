import { SynapseUserId } from "./index";

/*
CREATE TABLE user_threepids (
    user_id text NOT NULL,
    medium text NOT NULL,
    address text NOT NULL,
    validated_at bigint NOT NULL,
    added_at bigint NOT NULL
);
*/
export interface SUserThreePid {
  user_id: SynapseUserId;
  medium: string;
  address: string;
  validated_at: number;
  added_at: number;
}
