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

import { H3, Button } from "@vector-im/compound-web";
import { useSetAtom } from "jotai";
import { useTransition } from "react";

import { FragmentType, useFragment } from "../../gql";
import BlockList from "../BlockList/BlockList";
import {
  COMPAT_SESSION_FRAGMENT,
  endCompatSessionFamily,
  simplifyUrl,
} from "../CompatSession";
import DateTime from "../DateTime";

import SessionDetails from "./SessionDetails";

type Props = {
  session: FragmentType<typeof COMPAT_SESSION_FRAGMENT>;
};

const CompatSessionDetail: React.FC<Props> = ({ session }) => {
  const [pending, startTransition] = useTransition();
  const data = useFragment(COMPAT_SESSION_FRAGMENT, session);
  const endSession = useSetAtom(endCompatSessionFamily(data.id));

  // @TODO(kerrya) make this wait for session refresh properly
  // https://github.com/matrix-org/matrix-authentication-service/issues/1533
  const onSessionEnd = (): void => {
    startTransition(() => {
      endSession();
    });
  };

  const finishedAt = data.finishedAt
    ? [{ label: "Finished", value: <DateTime datetime={data.createdAt} /> }]
    : [];
  const sessionDetails = [
    { label: "ID", value: <code>{data.id}</code> },
    { label: "Device ID", value: <code>{data.deviceId}</code> },
    { label: "Signed in", value: <DateTime datetime={data.createdAt} /> },
    ...finishedAt,
  ];

  const clientDetails: { label: string; value: string | JSX.Element }[] = [];

  if (data.ssoLogin?.redirectUri) {
    clientDetails.push({
      label: "Name",
      value: simplifyUrl(data.ssoLogin.redirectUri),
    });
    clientDetails.push({
      label: "Uri",
      value: (
        <a target="_blank" href={data.ssoLogin?.redirectUri}>
          {data.ssoLogin?.redirectUri}
        </a>
      ),
    });
  }

  return (
    <div>
      <BlockList>
        <H3>{data.deviceId || data.id}</H3>
        <SessionDetails title="Session" details={sessionDetails} />
        {clientDetails.length > 0 ? (
          <SessionDetails title="Client" details={clientDetails} />
        ) : null}
        {!data.finishedAt && (
          <Button
            kind="destructive"
            size="sm"
            onClick={onSessionEnd}
            disabled={pending}
          >
            {/* @TODO(kerrya) put this back after pending state works properly */}
            {/* { pending && <LoadingSpinner />} */}
            End session
          </Button>
        )}
      </BlockList>
    </div>
  );
};

export default CompatSessionDetail;
