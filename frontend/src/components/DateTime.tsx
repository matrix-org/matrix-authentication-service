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

import {
  formatISO,
  intlFormat,
  intlFormatDistance,
  differenceInHours,
  parseISO,
} from "date-fns";

type Props = {
  className?: string;
  datetime: Date | string;
  now?: Date;
};

export const formatDate = (datetime: Date): string =>
  intlFormat(datetime, {
    year: "numeric",
    month: "short",
    day: "numeric",
    weekday: "short",
    hour: "numeric",
    minute: "numeric",
  });

/**
 * Formats a datetime
 * Uses distance when less than an hour ago
 * Else internationalised `Fri, 21 Jul 2023, 16:14`
 */
export const formatReadableDate = (datetime: Date, now: Date): string =>
  Math.abs(differenceInHours(now, datetime, { roundingMethod: "round" })) > 1
    ? formatDate(datetime)
    : intlFormatDistance(datetime, now);

const DateTime: React.FC<Props> = ({
  datetime: datetimeProps,
  now: nowProps,
  className,
}) => {
  const datetime =
    typeof datetimeProps === "string" ? parseISO(datetimeProps) : datetimeProps;
  const now = nowProps || new Date();
  const text = formatReadableDate(datetime, now);

  return (
    <time className={className} dateTime={formatISO(datetime)}>
      {text}
    </time>
  );
};

export default DateTime;
