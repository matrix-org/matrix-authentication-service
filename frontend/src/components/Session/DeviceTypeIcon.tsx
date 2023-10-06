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

import IconComputer from "@vector-im/compound-design-tokens/icons/computer.svg?react";
import IconMobile from "@vector-im/compound-design-tokens/icons/mobile.svg?react";
import IconUnknown from "@vector-im/compound-design-tokens/icons/unknown.svg?react";
import IconBrowser from "@vector-im/compound-design-tokens/icons/web-browser.svg?react";
import { FunctionComponent, SVGProps } from "react";

import { DeviceType } from "../../utils/parseUserAgent";

import styles from "./DeviceTypeIcon.module.css";

const deviceTypeToIcon: Record<
  DeviceType,
  FunctionComponent<SVGProps<SVGSVGElement> & { title?: string | undefined }>
> = {
  [DeviceType.Unknown]: IconUnknown,
  [DeviceType.Desktop]: IconComputer,
  [DeviceType.Mobile]: IconMobile,
  [DeviceType.Web]: IconBrowser,
};

const deviceTypeToLabel: Record<DeviceType, string> = {
  [DeviceType.Unknown]: "Unknown device type",
  [DeviceType.Desktop]: "Desktop",
  [DeviceType.Mobile]: "Mobile",
  [DeviceType.Web]: "Web",
};

const DeviceTypeIcon: React.FC<{ deviceType: DeviceType }> = ({
  deviceType,
}) => {
  const Icon = deviceTypeToIcon[deviceType];
  const label = deviceTypeToLabel[deviceType];

  return <Icon className={styles.icon} aria-label={label} />;
};

export default DeviceTypeIcon;
