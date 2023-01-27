import { ArgTypes, Decorator, Parameters } from "@storybook/react";
import { useLayoutEffect } from "react";
import { createMemoryRouter, RouterProvider } from "react-router-dom";
import "../src/index.css";

export const parameters: Parameters = {
  actions: { argTypesRegex: "^on[A-Z].*" },
  controls: {
    matchers: {
      color: /(background|color)$/i,
      date: /Date$/,
    },
  },
};

export const globalTypes: ArgTypes = {
  theme: {
    name: "Theme",
    description: "Global theme for components",
    defaultValue: "light",
    toolbar: {
      icon: "circlehollow",
      title: "Theme",
      items: [
        {
          title: "Light",
          value: "light",
          icon: "sun",
        },
        {
          title: "Dark",
          value: "dark",
          icon: "moon",
        },
      ],
    },
  },
};

const ThemeSwitcher: React.FC<{ theme?: "light" | "dark" }> = ({ theme }) => {
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

const withThemeProvider: Decorator = (Story, context) => {
  return (
    <>
      <ThemeSwitcher theme={context.globals.theme} />
      <Story />
    </>
  );
};

const withRouter: Decorator = (Story, _context) => {
  const router = createMemoryRouter([
    {
      path: "/*",
      element: <Story />,
    },
  ]);

  return <RouterProvider router={router} />;
};

export const decorators: Decorator[] = [withThemeProvider, withRouter];
