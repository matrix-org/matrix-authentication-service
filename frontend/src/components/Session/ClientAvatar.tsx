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

import { Avatar } from "@vector-im/compound-web";
import { CSSProperties } from "react";

import styles from "./ClientAvatar.module.css";

const ClientAvatar: React.FC<{
  name: string;
  logoUri?: string;
  /**
   * Render a fallback avatar using client name when truthy
   * Otherwise return null when no logoUri
   */
  withFallback?: boolean;
  size: string;
}> = ({ name, logoUri, withFallback, size }) => {
  // compound's lazy loading for avatars does not allow CORS requests
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
  if (withFallback) {
    return <Avatar size={size} id={name} name={name} src={logoUri} />;
  }
  return null;
};

export default ClientAvatar;
