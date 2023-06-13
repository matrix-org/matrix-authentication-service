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

type Props = {
  onNext: (() => void) | null;
  onPrev: (() => void) | null;
  count?: number;
  disabled?: boolean;
};

const PaginationControls: React.FC<Props> = ({
  onNext,
  onPrev,
  count,
  disabled,
}) => {
  return (
    <div className="grid items-center grid-cols-3 gap-2 my-2">
      <Button
        kind="secondary"
        size="sm"
        disabled={disabled || !onPrev}
        onClick={(): void => onPrev?.()}
      >
        Previous
      </Button>
      <div className="text-center">{count && <>Total: {count}</>}</div>
      <Button
        kind="secondary"
        size="sm"
        disabled={disabled || !onNext}
        onClick={(): void => onNext?.()}
      >
        Next
      </Button>
    </div>
  );
};

export default PaginationControls;
