import { UUID } from "./index";
import { MUserEmail } from "./MUserEmail";

export interface MUser {
  user_id: UUID<MUser>;
  username: string; // localpart only without @
  created_at: Date;
  primary_user_email_id?: UUID<MUserEmail>;
}
