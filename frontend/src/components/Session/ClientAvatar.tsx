// Copyright 2023 The Matrix.org Foundation C.I.C.
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

import { CSSProperties } from "react";

import styles from "./ClientAvatar.module.css";

/**
 * Render a client logo avatar when logoUri is truthy
 * Otherwise return null
 */
const ClientAvatar: React.FC<{
  name: string;
  logoUri?: string;
  size: string;
}> = ({ name, logoUri, size }) => {
  // compound's lazy loading for avatars does not allow CORS requests
  // so use our own avatar styled img
  if (logoUri) {
    return (
      <img
        className={styles.avatar}
        src={logoUri}
        alt={name}
        style={
          {
            "--mas-avatar-size": size,
          } as CSSProperties
        }
      />
    );
  }
  return null;
};

export default ClientAvatar;
