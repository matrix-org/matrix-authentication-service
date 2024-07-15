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

import IconComputer from "@vector-im/compound-design-tokens/assets/web/icons/computer";
import IconMobile from "@vector-im/compound-design-tokens/assets/web/icons/mobile";
import IconUnknown from "@vector-im/compound-design-tokens/assets/web/icons/unknown";
import IconBrowser from "@vector-im/compound-design-tokens/assets/web/icons/web-browser";
import { FunctionComponent, SVGProps } from "react";
import { useTranslation } from "react-i18next";

import { DeviceType } from "../../gql/graphql";

import styles from "./DeviceTypeIcon.module.css";

const deviceTypeToIcon: Record<
  DeviceType,
  FunctionComponent<SVGProps<SVGSVGElement> & { title?: string | undefined }>
> = {
  [DeviceType.Unknown]: IconUnknown,
  [DeviceType.Pc]: IconComputer,
  [DeviceType.Mobile]: IconMobile,
  [DeviceType.Tablet]: IconBrowser,
};

const DeviceTypeIcon: React.FC<{ deviceType: DeviceType }> = ({
  deviceType,
}) => {
  const { t } = useTranslation();

  const Icon = deviceTypeToIcon[deviceType];

  const deviceTypeToLabel: Record<DeviceType, string> = {
    [DeviceType.Unknown]: t("frontend.device_type_icon_label.unknown"),
    [DeviceType.Pc]: t("frontend.device_type_icon_label.pc"),
    [DeviceType.Mobile]: t("frontend.device_type_icon_label.mobile"),
    [DeviceType.Tablet]: t("frontend.device_type_icon_label.tablet"),
  };

  const label = deviceTypeToLabel[deviceType];

  return <Icon className={styles.deviceTypeIcon} aria-label={label} />;
};

export default DeviceTypeIcon;
