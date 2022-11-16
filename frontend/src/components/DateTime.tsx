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

const DateTime = ({
  datetime: datetimeProps,
  now: nowProps,
  className,
}: Props) => {
  const datetime =
    typeof datetimeProps === "string" ? parseISO(datetimeProps) : datetimeProps;
  const now = nowProps || new Date();
  const text =
    Math.abs(differenceInHours(now, datetime, { roundingMethod: "round" })) > 1
      ? intlFormat(datetime, {
          year: "numeric",
          month: "short",
          day: "numeric",
          weekday: "short",
          hour: "numeric",
          minute: "numeric",
        })
      : intlFormatDistance(datetime, now);
  return (
    <time className={className} dateTime={formatISO(datetime)}>
      {text}
    </time>
  );
};

export default DateTime;
