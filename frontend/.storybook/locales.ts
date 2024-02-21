export type LocalazyLanguage = {
    language: string;
    region: string;
    script: string;
    isRtl: boolean;
    localizedName: string;
    name: string;
    pluralType: (n: number) => "zero" | "one" | "two" | "many" | "few" | "other";
};
export type LocalazyFile = {
    cdnHash: string;
    file: string;
    path: string;
    library: string;
    module: string;
    buildType: string;
    productFlavors: string[];
    cdnFiles: { [lang:string]: string };
};
export type LocalazyMetadata = {
    projectUrl: string;
    baseLocale: string;
    languages: LocalazyLanguage[];
    files: LocalazyFile[];
};
     
const localazyMetadata: LocalazyMetadata = {
  projectUrl: "https://localazy.com/p/matrix-authentication-service",
  baseLocale: "en",
  languages: [
    {
      language: "de",
      region: "",
      script: "",
      isRtl: false,
      name: "German",
      localizedName: "Deutsch",
      pluralType: (n) => { return (n===1) ? "one" : "other"; }
    },
    {
      language: "en",
      region: "",
      script: "",
      isRtl: false,
      name: "English",
      localizedName: "English",
      pluralType: (n) => { return (n===1) ? "one" : "other"; }
    },
    {
      language: "fr",
      region: "",
      script: "",
      isRtl: false,
      name: "French",
      localizedName: "Français",
      pluralType: (n) => { return (n===0 || n===1) ? "one" : "other"; }
    },
    {
      language: "zh",
      region: "",
      script: "Hans",
      isRtl: false,
      name: "Simplified Chinese",
      localizedName: "简体中文",
      pluralType: (n) => { return "other"; }
    }
  ],
  files: [
    {
      cdnHash: "7c203a8ac8bd48c3c4609a8effcd0fbac430f9b2",
      file: "frontend.json",
      path: "",
      library: "",
      module: "",
      buildType: "",
      productFlavors: [],
      cdnFiles: {
        "de#": "https://delivery.localazy.com/_a7686032324574572744739e0707/_e0/7c203a8ac8bd48c3c4609a8effcd0fbac430f9b2/de/frontend.json",
        "en#": "https://delivery.localazy.com/_a7686032324574572744739e0707/_e0/7c203a8ac8bd48c3c4609a8effcd0fbac430f9b2/en/frontend.json",
        "fr#": "https://delivery.localazy.com/_a7686032324574572744739e0707/_e0/7c203a8ac8bd48c3c4609a8effcd0fbac430f9b2/fr/frontend.json",
        "zh#Hans": "https://delivery.localazy.com/_a7686032324574572744739e0707/_e0/7c203a8ac8bd48c3c4609a8effcd0fbac430f9b2/zh-Hans/frontend.json"
      }
    },
    {
      cdnHash: "5b69b0350dccfd47c245a5d41c1b9fdf6912cc6e",
      file: "file.json",
      path: "",
      library: "",
      module: "",
      buildType: "",
      productFlavors: [],
      cdnFiles: {
        "de#": "https://delivery.localazy.com/_a7686032324574572744739e0707/_e0/5b69b0350dccfd47c245a5d41c1b9fdf6912cc6e/de/file.json",
        "en#": "https://delivery.localazy.com/_a7686032324574572744739e0707/_e0/5b69b0350dccfd47c245a5d41c1b9fdf6912cc6e/en/file.json",
        "fr#": "https://delivery.localazy.com/_a7686032324574572744739e0707/_e0/5b69b0350dccfd47c245a5d41c1b9fdf6912cc6e/fr/file.json",
        "zh#Hans": "https://delivery.localazy.com/_a7686032324574572744739e0707/_e0/5b69b0350dccfd47c245a5d41c1b9fdf6912cc6e/zh-Hans/file.json"
      }
    }
  ]
};

export default localazyMetadata;