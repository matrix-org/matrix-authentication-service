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

type Props = {
  disabled?: boolean;
  className?: string;
} & React.HTMLProps<HTMLInputElement>;

const Input: React.FC<Props> = ({ disabled, className, ...props }) => {
  const disabledClass = disabled
    ? "bg-grey-50 dark:bg-grey-400"
    : "bg-white dark:bg-grey-450";
  const fullClassName = `${className} px-2 py-1 border-2 border-grey-50 dark:border-grey-400 dark:text-white placeholder-grey-100 dark:placeholder-grey-150 rounded-lg ${disabledClass}`;
  return <input disabled={disabled} className={fullClassName} {...props} />;
};

export default Input;
