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

import { lazy, Suspense } from "react";
import { createBrowserRouter, Outlet, RouterProvider } from "react-router-dom";

import Layout from "./components/Layout";
import LoadingSpinner from "./components/LoadingSpinner";

const Home = lazy(() => import("./pages/Home"));
const OAuth2Client = lazy(() => import("./pages/OAuth2Client"));
const BrowserSession = lazy(() => import("./pages/BrowserSession"));

export const router = createBrowserRouter(
  [
    {
      path: "/",
      element: (
        <Layout>
          <Suspense fallback={<LoadingSpinner />}>
            <Outlet />
          </Suspense>
        </Layout>
      ),
      children: [
        {
          index: true,
          element: <Home />,
        },
        {
          path: "dumb",
          element: <>Hello from another dumb page.</>,
        },
        {
          path: "client/:id",
          element: <OAuth2Client />,
        },
        {
          path: "session/:id",
          element: <BrowserSession />,
        },
      ],
    },
  ],
  {
    basename: window.APP_CONFIG.root,
  }
);

const Router = () => <RouterProvider router={router} />;

export default Router;
