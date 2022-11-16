import { useLayoutEffect } from "react";
import { createMemoryRouter, RouterProvider } from "react-router-dom";
import "../src/index.css";

export const parameters = {
  actions: { argTypesRegex: "^on[A-Z].*" },
  controls: {
    matchers: {
      color: /(background|color)$/i,
      date: /Date$/,
    },
  },
};

export const globalTypes = {
  theme: {
    name: "Theme",
    description: "Global theme for components",
    defaultValue: "light",
    toolbar: {
      title: "Theme",
      items: [
        {
          title: "Light",
          value: "light",
          icon: "circle",
        },
        {
          title: "Dark",
          value: "dark",
          icon: "circlehollow",
        },
      ],
    },
  },
};

const ThemeSwitcher = ({ theme }) => {
  useLayoutEffect(() => {
    if (theme === "dark") {
      document.documentElement.classList.add("dark");
    } else {
      document.documentElement.classList.remove("dark");
    }

    return () => document.documentElement.classList.remove("dark");
  }, [theme]);

  return null;
};

const withThemeProvider = (Story, context) => {
  return (
    <>
      <ThemeSwitcher theme={context.globals.theme} />
      <Story />
    </>
  );
};

const withRouter = (Story, context) => {
  const router = createMemoryRouter([
    {
      path: "/*",
      element: <Story />,
    },
  ]);

  return <RouterProvider router={router} />;
};

export const decorators = [withThemeProvider, withRouter];
