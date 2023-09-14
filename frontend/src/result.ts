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

const RESULT = Symbol("Result");
const ERR = Symbol("Err");
const OK = Symbol("Ok");

/**
 * An `Ok` is a type that represents a successful result.
 */
export type Ok<T> = {
  [RESULT]: typeof OK;
  [OK]: T;
};

/**
 * An `Err` is a type that represents an error.
 */
export type Err<E> = {
  [RESULT]: typeof ERR;
  [ERR]: E;
};

/**
 * A `Result` is a type that represents either an `Ok` or an `Err`.
 */
export type Result<T, E> = Ok<T> | Err<E>;

// Construct an `Ok`
export const ok = <T>(data: T): Ok<T> => ({ [RESULT]: OK, [OK]: data });

// Construct an `Err`
export const err = <E>(error: E): Err<E> => ({
  [RESULT]: ERR,
  [ERR]: error,
});

// Check if a `Result` is an `Ok`
export const isOk = <T, E>(result: Result<T, E>): result is Ok<T> =>
  result[RESULT] === OK;

// Check if a `Result` is an `Err`
export const isErr = <T, E>(result: Result<T, E>): result is Err<E> =>
  result[RESULT] === ERR;

// Extract the data from an `Ok`
export const unwrapOk = <T>(result: Ok<T>): T => result[OK];

// Extract the error from an `Err`
export const unwrapErr = <E>(result: Err<E>): E => result[ERR];

/**
 * Check result for error and throw unwrapped error
 * Otherwise return unwrapped Ok result
 */
export const unwrap = <T, E>(result: Result<T, E>): T => {
  if (isErr(result)) {
    throw unwrapErr(result);
  }
  return unwrapOk(result);
};
