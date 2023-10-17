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

import i18n from "i18next";
import LanguageDetector from "i18next-browser-languagedetector";
import I18NextHttpBackend from "i18next-http-backend";
import { initReactI18next } from "react-i18next";

const languageDetector = new LanguageDetector();

i18n
  .use(I18NextHttpBackend)
  .use(languageDetector)
  .use(initReactI18next)
  .init({
    fallbackLng: "en",
    keySeparator: ".",
    pluralSeparator: ":",
    interpolation: {
      escapeValue: false, // React has built-in XSS protections
    },
    backend: {
      loadPath: "/locales/{{lng}}.json",
    },
  });

import.meta.hot?.on("locales-update", () => {
    i18n.reloadResources().then(() => {
        i18n.changeLanguage(i18n.language)
    })
});

export default i18n;
