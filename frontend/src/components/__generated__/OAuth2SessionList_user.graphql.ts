/**
 * @generated SignedSource<<8cb936a8cc1a9ab2a877a4ea92622c88>>
 * @lightSyntaxTransform
 * @nogrep
 */

/* tslint:disable */
/* eslint-disable */
// @ts-nocheck

import { ReaderFragment, RefetchableFragment } from 'relay-runtime';
import { FragmentRefs } from "relay-runtime";
export type OAuth2SessionList_user$data = {
  readonly id: string;
  readonly oauth2Sessions: {
    readonly edges: ReadonlyArray<{
      readonly cursor: string;
      readonly node: {
        readonly id: string;
        readonly " $fragmentSpreads": FragmentRefs<"OAuth2Session_session">;
      };
    }>;
  };
  readonly " $fragmentType": "OAuth2SessionList_user";
};
export type OAuth2SessionList_user$key = {
  readonly " $data"?: OAuth2SessionList_user$data;
  readonly " $fragmentSpreads": FragmentRefs<"OAuth2SessionList_user">;
};

import OAuth2SessionListQuery_graphql from './OAuth2SessionListQuery.graphql';

const node: ReaderFragment = (function(){
var v0 = [
  "oauth2Sessions"
],
v1 = {
  "alias": null,
  "args": null,
  "kind": "ScalarField",
  "name": "id",
  "storageKey": null
};
return {
  "argumentDefinitions": [
    {
      "kind": "RootArgument",
      "name": "count"
    },
    {
      "kind": "RootArgument",
      "name": "cursor"
    }
  ],
  "kind": "Fragment",
  "metadata": {
    "connection": [
      {
        "count": "count",
        "cursor": "cursor",
        "direction": "forward",
        "path": (v0/*: any*/)
      }
    ],
    "refetch": {
      "connection": {
        "forward": {
          "count": "count",
          "cursor": "cursor"
        },
        "backward": null,
        "path": (v0/*: any*/)
      },
      "fragmentPathInResult": [
        "node"
      ],
      "operation": OAuth2SessionListQuery_graphql,
      "identifierField": "id"
    }
  },
  "name": "OAuth2SessionList_user",
  "selections": [
    {
      "alias": "oauth2Sessions",
      "args": null,
      "concreteType": "Oauth2SessionConnection",
      "kind": "LinkedField",
      "name": "__OAuth2SessionList_user_oauth2Sessions_connection",
      "plural": false,
      "selections": [
        {
          "alias": null,
          "args": null,
          "concreteType": "Oauth2SessionEdge",
          "kind": "LinkedField",
          "name": "edges",
          "plural": true,
          "selections": [
            {
              "alias": null,
              "args": null,
              "kind": "ScalarField",
              "name": "cursor",
              "storageKey": null
            },
            {
              "alias": null,
              "args": null,
              "concreteType": "Oauth2Session",
              "kind": "LinkedField",
              "name": "node",
              "plural": false,
              "selections": [
                (v1/*: any*/),
                {
                  "args": null,
                  "kind": "FragmentSpread",
                  "name": "OAuth2Session_session"
                },
                {
                  "alias": null,
                  "args": null,
                  "kind": "ScalarField",
                  "name": "__typename",
                  "storageKey": null
                }
              ],
              "storageKey": null
            }
          ],
          "storageKey": null
        },
        {
          "alias": null,
          "args": null,
          "concreteType": "PageInfo",
          "kind": "LinkedField",
          "name": "pageInfo",
          "plural": false,
          "selections": [
            {
              "alias": null,
              "args": null,
              "kind": "ScalarField",
              "name": "endCursor",
              "storageKey": null
            },
            {
              "alias": null,
              "args": null,
              "kind": "ScalarField",
              "name": "hasNextPage",
              "storageKey": null
            }
          ],
          "storageKey": null
        }
      ],
      "storageKey": null
    },
    (v1/*: any*/)
  ],
  "type": "User",
  "abstractKey": null
};
})();

(node as any).hash = "17ef23458a73705550aa33e7f73e41cf";

export default node;
