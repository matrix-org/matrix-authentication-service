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

import { useAtomValue } from "jotai";
import { atomFamily } from "jotai/utils";
import { atomWithQuery } from "jotai-urql";

import { mapQueryAtom } from "../atoms";
import ErrorBoundary from "../components/ErrorBoundary";
import GraphQLError from "../components/GraphQLError";
import VerifyEmailComponent from "../components/VerifyEmail";
import { graphql } from "../gql";
import { isErr, unwrapErr, unwrapOk } from "../result";

const QUERY = graphql(/* GraphQL */ `
  query VerifyEmailQuery($id: ID!) {
    userEmail(id: $id) {
      ...UserEmail_verifyEmail
    }
  }
`);

const verifyEmailFamily = atomFamily((id: string) => {
  const verifyEmailQueryAtom = atomWithQuery({
    query: QUERY,
    getVariables: () => ({ id }),
  });

  const verifyEmailAtom = mapQueryAtom(
    verifyEmailQueryAtom,
    (data) => data?.userEmail,
  );

  return verifyEmailAtom;
});

const VerifyEmail: React.FC<{ id: string }> = ({ id }) => {
  const result = useAtomValue(verifyEmailFamily(id));
  if (isErr(result)) return <GraphQLError error={unwrapErr(result)} />;

  const email = unwrapOk(result);
  if (email == null) return <>Unknown email</>;

  return (
    <ErrorBoundary>
      <VerifyEmailComponent email={email} />
    </ErrorBoundary>
  );
};

export default VerifyEmail;
