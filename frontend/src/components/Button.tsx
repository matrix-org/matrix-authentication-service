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
  children: string;
  compact?: boolean;
  ghost?: boolean;
  disabled?: boolean;
} & React.HTMLProps<HTMLButtonElement>;

const Button: React.FC<Props> = ({
  children,
  compact,
  ghost,
  disabled,
  ...props
}) => {
  const sizeClass = compact ? "py-1 px-3" : "py-1 px-5";

  let ghostClass = "";
  let normalClass = "";

  if (disabled) {
    ghostClass = "opacity-30 border border-accent text-accent";
    normalClass = "opacity-30 border border-accent bg-accent text-white";
  } else {
    ghostClass = "border-accent border hover:bg-accent/10 text-accent";
    normalClass =
      "bg-accent border border-accent hover:bg-accent/75 hover:border-accent/75 text-white";
  }

  const colors = ghost ? ghostClass : normalClass;

  return (
    <button
      {...props}
      type="button"
      className={`rounded-lg font-semibold ${colors} ${sizeClass}`}
      disabled={disabled}
    >
      {children}
    </button>
  );
};

export default Button;
