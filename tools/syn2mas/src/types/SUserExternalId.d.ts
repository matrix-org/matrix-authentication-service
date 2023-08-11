import { SynapseUserId } from "./index";

export interface SUserExternalId {
  auth_provider: string;
  external_id: string;
  user_id: SynapseUserId;
}
