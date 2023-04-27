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

import Button from "./Button";

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
    <div className="grid items-center grid-cols-3 gap-2">
      {onPrev ? (
        <Button compact disabled={disabled} ghost onClick={onPrev}>
          Previous
        </Button>
      ) : (
        <Button compact disabled ghost>
          Previous
        </Button>
      )}
      {count !== undefined ? (
        <div className="text-center">Total: {count}</div>
      ) : (
        <div></div>
      )}
      {onNext ? (
        <Button compact disabled={disabled} ghost onClick={onNext}>
          Next
        </Button>
      ) : (
        <Button compact disabled ghost>
          Next
        </Button>
      )}
    </div>
  );
};

export default PaginationControls;
