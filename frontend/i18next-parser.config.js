export default {
    keySeparator: ".",
    pluralSeparator: ":",
    defaultNamespace: "frontend",
    lexers: {
        ts: [
            {
                lexer: "JavascriptLexer",
                functions: ["t", "translatedError"],
                functionsNamespace: ["useTranslation", "withTranslation"],
            },
        ],
    },
    locales: ["en"],
    output: "public/locales/$LOCALE.json",
    input: ["src/**/*.{ts,tsx}"],
    sort: true,
};
