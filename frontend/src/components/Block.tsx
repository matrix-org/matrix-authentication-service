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

type Props = {
  children: React.ReactNode;
  highlight?: boolean;
  className?: string;
};

const Block: React.FC<Props> = ({ children, highlight, className }) => {
  return (
    <div
      className={`p-4 dark:text-white grid rounded ${className} ${
        highlight
          ? "border-2 border-grey-50 dark:border-grey-450 bg-white dark:bg-black"
          : "bg-grey-50 dark:bg-grey-450"
      }`}
    >
      {children}
    </div>
  );
};

export default Block;
