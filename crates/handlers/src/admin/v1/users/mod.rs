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

mod add;
mod by_username;
mod deactivate;
mod get;
mod list;
mod lock;
mod set_admin;
mod set_password;
mod unlock;

pub use self::{
    add::{doc as add_doc, handler as add},
    by_username::{doc as by_username_doc, handler as by_username},
    deactivate::{doc as deactivate_doc, handler as deactivate},
    get::{doc as get_doc, handler as get},
    list::{doc as list_doc, handler as list},
    lock::{doc as lock_doc, handler as lock},
    set_admin::{doc as set_admin_doc, handler as set_admin},
    set_password::{doc as set_password_doc, handler as set_password},
    unlock::{doc as unlock_doc, handler as unlock},
};
