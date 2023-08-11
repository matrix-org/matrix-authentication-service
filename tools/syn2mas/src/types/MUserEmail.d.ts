import { MUser } from "./MUser";
import { UUID } from "./index";

/*
+---------------+--------------------------+-----------+
| Column        | Type                     | Modifiers |
|---------------+--------------------------+-----------|
| user_email_id | uuid                     |  not null |
| user_id       | uuid                     |  not null |
| email         | text                     |  not null |
| created_at    | timestamp with time zone |  not null |
| confirmed_at  | timestamp with time zone |           |
+---------------+--------------------------+-----------+
*/

export interface MUserEmail {
  user_email_id: UUID<MUserEmail>;
  user_id: UUID<MUser>;
  email: string;
  created_at: Date;
  confirmed_at?: Date;
}
