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

import { Button } from "@vector-im/compound-web";
import { atom, useAtomValue, useSetAtom } from "jotai";
import { atomFamily } from "jotai/utils";
import { atomWithQuery } from "jotai-urql";
import { PropsWithChildren, useState, useTransition } from "react";

import { mapQueryAtom } from "../../atoms";
import { graphql } from "../../gql";
import { SessionState, PageInfo, AppSessionEdge } from "../../gql/graphql";
import {
  atomForCurrentPagination,
  atomWithPagination,
  Pagination,
} from "../../pagination";
import { isOk, unwrap, unwrapOk } from "../../result";
import { useEndAppSessions } from "../../utils/session/useEndAppSession";
import BlockList from "../BlockList";
import CompatSession from "../CompatSession";
import OAuth2Session from "../OAuth2Session";
import PaginationControls from "../PaginationControls";
import EndSessionButton from "../Session/EndSessionButton";
import SelectableSession from "../Session/SelectableSession";
import SessionListHeader from "../SessionList/SessionListHeader";

const QUERY = graphql(/* GraphQL */ `
  query AppSessionList(
    $userId: ID!
    $state: SessionState
    $first: Int
    $after: String
    $last: Int
    $before: String
  ) {
    user(id: $userId) {
      id
      appSessions(
        first: $first
        after: $after
        last: $last
        before: $before
        state: $state
      ) {
        totalCount

        edges {
          cursor
          node {
            __typename
            ...CompatSession_session
            ...OAuth2Session_session
          }
        }

        pageInfo {
          hasNextPage
          hasPreviousPage
          startCursor
          endCursor
        }
      }
    }
  }
`);

const filterAtom = atom<SessionState | null>(SessionState.Active);
const currentPaginationAtom = atomForCurrentPagination();

export const appSessionListFamily = atomFamily((userId: string) => {
  const appSessionListQuery = atomWithQuery({
    query: QUERY,
    getVariables: (get) => ({
      userId,
      state: get(filterAtom),
      ...get(currentPaginationAtom),
    }),
  });

  const appSessionList = mapQueryAtom(
    appSessionListQuery,
    (data) => data.user?.appSessions || null,
  );

  return appSessionList;
});

const pageInfoFamily = atomFamily((userId: string) => {
  const pageInfoAtom = atom(async (get): Promise<PageInfo | null> => {
    const result = await get(appSessionListFamily(userId));
    return (isOk(result) && unwrapOk(result)?.pageInfo) || null;
  });
  return pageInfoAtom;
});

const paginationFamily = atomFamily((userId: string) => {
  const paginationAtom = atomWithPagination(
    currentPaginationAtom,
    pageInfoFamily(userId),
  );

  return paginationAtom;
});

// A type-safe way to ensure we've handled all session types
const unknownSessionType = (type: never): never => {
  throw new Error(`Unknown session type: ${type}`);
};

const SelectableSessionWrapper: React.FC<
  PropsWithChildren<{
    session: AppSessionEdge;
    selection: AppSessionEdge[];
    onSelect: (session: AppSessionEdge) => void;
  }>
> = ({ session, selection, onSelect, children }) => (
  <SelectableSession
    disabled={!!session.node.finishedAt}
    isSelected={selection.includes(session)}
    onSelect={(): void => onSelect(session)}
  >
    {children}
  </SelectableSession>
);

const AppSessionsList: React.FC<{ userId: string }> = ({ userId }) => {
  const [pending, startTransition] = useTransition();
  const [selection, setSelection] = useState<AppSessionEdge[]>([]);
  const result = useAtomValue(appSessionListFamily(userId));
  const setPagination = useSetAtom(currentPaginationAtom);
  const [prevPage, nextPage] = useAtomValue(paginationFamily(userId));

  const endAppSessions = useEndAppSessions();

  const appSessions = unwrap(result);
  if (!appSessions) return <>Failed to load app sessions</>;

  const paginate = (pagination: Pagination): void => {
    startTransition(() => {
      setPagination(pagination);
      // clear selection on paging
      setSelection([]);
    });
  };

  const onSelect = (session: AppSessionEdge): void => {
    if (selection.includes(session)) {
      setSelection(
        selection.filter((selectedSession) => selectedSession !== session),
      );
    } else {
      setSelection([...selection, session]);
    }
  };

  const endSessions = async (): Promise<void> => {
    await endAppSessions(selection);
    setSelection([]);
  };

  return (
    <BlockList>
      <SessionListHeader title="Apps">
        {!!selection.length && (
          <>
            <Button
              kind="tertiary"
              size="sm"
              onClick={(): void => setSelection([])}
            >
              Clear
            </Button>
            <EndSessionButton
              endSession={endSessions}
              // sessionCount={selection.length}
            />
          </>
        )}
      </SessionListHeader>
      {appSessions.edges.map((session) => {
        const type = session.node.__typename;
        switch (type) {
          case "Oauth2Session":
            return (
              <SelectableSessionWrapper
                key={session.cursor}
                session={session as AppSessionEdge}
                onSelect={onSelect}
                selection={selection}
              >
                <OAuth2Session session={session.node} />
              </SelectableSessionWrapper>
            );
          case "CompatSession":
            return (
              <SelectableSessionWrapper
                key={session.cursor}
                session={session as AppSessionEdge}
                onSelect={onSelect}
                selection={selection}
              >
                <CompatSession session={session.node} />
              </SelectableSessionWrapper>
            );
          default:
            unknownSessionType(type);
        }
      })}
      <PaginationControls
        onPrev={prevPage ? (): void => paginate(prevPage) : null}
        onNext={nextPage ? (): void => paginate(nextPage) : null}
        count={appSessions.totalCount}
        disabled={pending}
      />
    </BlockList>
  );
};

export default AppSessionsList;
