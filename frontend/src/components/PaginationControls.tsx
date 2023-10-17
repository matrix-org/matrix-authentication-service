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

import { Button } from "@vector-im/compound-web";
import { useTranslation } from "react-i18next";

type Props = {
  onNext: (() => void) | null;
  onPrev: (() => void) | null;
  // automatically hide the component when there are no onNext/onPrev
  autoHide?: boolean;
  count?: number;
  disabled?: boolean;
};

const PaginationControls: React.FC<Props> = ({
  onNext,
  onPrev,
  autoHide,
  count,
  disabled,
}) => {
  const { t } = useTranslation();

  if (autoHide && !onNext && !onPrev) {
    return null;
  }
  return (
    <div className="grid items-center grid-cols-3 gap-2">
      <Button
        kind="secondary"
        size="sm"
        disabled={disabled || !onPrev}
        onClick={(): void => onPrev?.()}
      >
        {t("common.previous")}
      </Button>
      <div className="text-center">
        {count !== undefined ? (
          <>{t("frontend.pagination_controls.total", { totalCount: count })}</>
        ) : null}
      </div>
      <Button
        kind="secondary"
        size="sm"
        disabled={disabled || !onNext}
        onClick={(): void => onNext?.()}
      >
        {t("common.next")}
      </Button>
    </div>
  );
};

export default PaginationControls;
