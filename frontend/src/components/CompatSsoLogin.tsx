// Copyright 2022 The Matrix.org Foundation C.I.C.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import type { CompatSsoLogin_login$key } from "./__generated__/CompatSsoLogin_login.graphql";
import { graphql, useFragment } from "react-relay";

type Props = {
  login: CompatSsoLogin_login$key;
};

const CompatSsoLogin: React.FC<Props> = ({ login }) => {
  const data = useFragment(
    graphql`
      fragment CompatSsoLogin_login on CompatSsoLogin {
        id
        redirectUri
      }
    `,
    login
  );

  return <>{data.redirectUri}</>;
};

export default CompatSsoLogin;
