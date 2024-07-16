// Copyright 2024 The Matrix.org Foundation C.I.C.
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

/// A filter which can be applied to a query
pub(crate) trait Filter {
    /// Generate a condition for the filter
    ///
    /// # Parameters
    ///
    /// * `has_joins`: Whether the condition has relationship joined or not
    fn generate_condition(&self, has_joins: bool) -> impl sea_query::IntoCondition;
}

pub(crate) trait StatementExt {
    /// Apply the filter to the query
    ///
    /// The query must NOT have any relationship joined
    fn apply_filter<F: Filter>(&mut self, filter: F) -> &mut Self;
}

pub(crate) trait StatementWithJoinsExt {
    /// Apply the filter to the query
    ///
    /// The query MUST have any relationship joined
    fn apply_filter_with_joins<F: Filter>(&mut self, filter: F) -> &mut Self;
}

impl StatementWithJoinsExt for sea_query::SelectStatement {
    fn apply_filter_with_joins<F: Filter>(&mut self, filter: F) -> &mut Self {
        let condition = filter.generate_condition(true);
        self.cond_where(condition)
    }
}

impl StatementExt for sea_query::SelectStatement {
    fn apply_filter<F: Filter>(&mut self, filter: F) -> &mut Self {
        let condition = filter.generate_condition(false);
        self.cond_where(condition)
    }
}

impl StatementExt for sea_query::UpdateStatement {
    fn apply_filter<F: Filter>(&mut self, filter: F) -> &mut Self {
        let condition = filter.generate_condition(false);
        self.cond_where(condition)
    }
}

impl StatementExt for sea_query::DeleteStatement {
    fn apply_filter<F: Filter>(&mut self, filter: F) -> &mut Self {
        let condition = filter.generate_condition(false);
        self.cond_where(condition)
    }
}
