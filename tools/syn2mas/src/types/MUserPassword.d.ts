import { MUser } from "./MUser";
import { UUID } from "./index";

export interface MUserPassword {
  user_password_id: UUID<MUserPassword>;
  user_id: UUID<MUser>;
  hashed_password: string;
  created_at: Date;
  version: number;
  upgraded_from_id?: UUID<MUserPassword>;
}
