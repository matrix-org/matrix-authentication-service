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

import { ErrorInfo, ReactNode, PureComponent } from "react";

import GenericError from "./GenericError";
import Layout from "./Layout";

interface Props {
  children: ReactNode;
}

interface IState {
  error?: Error;
}

/**
 * This error boundary component can be used to wrap large content areas and
 * catch exceptions during rendering in the component tree below them.
 */
export default class ErrorBoundary extends PureComponent<Props, IState> {
  public constructor(props: Props) {
    super(props);

    this.state = {};
  }

  public static getDerivedStateFromError(error: Error): Partial<IState> {
    // Side effects are not permitted here, so we only update the state so
    // that the next render shows an error message.
    return { error };
  }

  public componentDidCatch(error: Error, { componentStack }: ErrorInfo): void {
    console.error(error);
    console.error(
      "The above error occurred while React was rendering the following components:",
      componentStack,
    );
  }

  public render(): ReactNode {
    if (this.state.error) {
      // We ask the child components not to suspend, as this error boundary won't be in a Suspense boundary.
      return (
        <Layout dontSuspend>
          <GenericError dontSuspend error={this.state.error} />
        </Layout>
      );
    }

    return this.props.children;
  }
}
