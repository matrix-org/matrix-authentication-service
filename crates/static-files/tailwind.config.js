// Copyright 2021 The Matrix.org Foundation C.I.C.
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

module.exports = {
  mode: "jit",
  content: ["../templates/src/res/**/*.html"],
  theme: {
    extend: {
      colors: {
        accent: '#0DBD8B',
        alert: '#FF5B55',
        links: '#0086E6',
        'grey-25': '#F4F6FA',
        'grey-50': '#E3E8F0',
        'grey-100': '#C1C6CD',
        'grey-150': '#8D97A5',
        'grey-200': '#737D8C',
        'grey-250': '#A9B2BC',
        'grey-300': '#8E99A4',
        'grey-400': '#6F7882',
        'grey-450': '#394049',
        'black-800': '#15191E',
        'black-900': '#17191C',
        'black-950': '#21262C',
        'ice': '#F4F9FD',
      },
    },
  },
  variants: {
    extend: {},
  },
  plugins: [
    require('@tailwindcss/forms'),
  ],
}
