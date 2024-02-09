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

import { default as i18n, InitOptions } from "i18next";
import LanguageDetector, {
  DetectorOptions,
} from "i18next-browser-languagedetector";
import I18NextHttpBackend, { HttpBackendOptions } from "i18next-http-backend";
import { initReactI18next } from "react-i18next";

// This generates a map of locale names to their URL (based on import.meta.url), which looks like this:
// {
//   "../locales/en.json": "/whatever/assets/root/locales/en-aabbcc.json",
//   ...
// }
const locales = import.meta.glob<string>("../locales/*.json", {
  query: "?url",
  import: "default",
  eager: true,
});

const getLocaleUrl = (name: string): string =>
  locales[`../locales/${name}.json`];

const supportedLngs = Object.keys(locales).map(
  (url) => url.match(/\/([^/]+)\.json$/)![1],
);

i18n
  .use(I18NextHttpBackend)
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    fallbackLng: "en",
    keySeparator: ".",
    pluralSeparator: ":",
    supportedLngs,
    detection: {
      order: ["navigator", "htmlTag"],
    } satisfies DetectorOptions,
    interpolation: {
      escapeValue: false, // React has built-in XSS protections
    },
    backend: {
      crossDomain: true,
      loadPath(lngs: string[], _ns: string[]): string {
        return getLocaleUrl(lngs[0]);
      },
      requestOptions: {
        credentials: "same-origin",
      },
    },
  } satisfies InitOptions<HttpBackendOptions>);

import.meta.hot?.on("locales-update", () => {
  i18n.reloadResources().then(() => {
    i18n.changeLanguage(i18n.language);
  });
});

export default i18n;
