-- Copyright 2023 The Matrix.org Foundation C.I.C.
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

/**
 * This fully drops any existing push_job functions, as we're not relying on them anymore
 */

-- Temporarily change the client_min_messages to suppress the NOTICEs
SET client_min_messages = 'ERROR';

DROP FUNCTION IF EXISTS apalis.push_job(
    job_type text,
    job json,
    job_id  text,
    status  text,
    run_at timestamptz,
    max_attempts integer
);

DROP FUNCTION IF EXISTS apalis.push_job(
    job_type text,
    job json,
    status text,
    run_at timestamptz,
    max_attempts integer
);

-- Reset the client_min_messages
RESET client_min_messages;

/**
 * Remove the old applied migrations in case they were applied:
 *  - 20220709210445_add_job_fn.sql
 *  - 20230330210841_replace_add_job_fn.sql
 *  - 20230408110421_drop_old_push_job.sql
 */
DELETE FROM public._sqlx_migrations
WHERE version IN (
    20220709210445,
    20230330210841,
    20230408110421
);