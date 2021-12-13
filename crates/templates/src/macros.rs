// Copyright 2021 The Matrix.org Foundation C.I.C.
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

/// Count the number of tokens. Used to have a fixed-sized array for the
/// templates list.
macro_rules! count {
    () => (0_usize);
    ( $x:tt $($xs:tt)* ) => (1_usize + count!($($xs)*));
}

/// Macro that helps generating helper function that renders a specific template
/// with a strongly-typed context. It also register the template in a static
/// array to help detecting missing templates at startup time.
///
/// The syntax looks almost like a function to confuse syntax highlighter as
/// little as possible.
#[macro_export]
macro_rules! register_templates {
    {
        $(
            extra = { $( $extra_template:expr ),* $(,)? };
        )?

        $(
            // Match any attribute on the function, such as #[doc], #[allow(dead_code)], etc.
            $( #[ $attr:meta ] )*
            // The function name
            pub fn $name:ident
                // Optional list of generics. Taken from
                // https://newbedev.com/rust-macro-accepting-type-with-generic-parameters
                $(< $( $lt:tt $( : $clt:tt $(+ $dlt:tt )* )? ),+ >)?
                // Type of context taken by the template
                ( $param:ty )
            {
                // The name of the template file
                $template:expr
            }
        )*
    } => {
        /// List of registered templates
        static TEMPLATES: [(&'static str, Option<&'static str>); count!( $( $template )* )] = [
            $( (
                $template,
                if cfg!(feature = "dev") {
                    None
                } else {
                    Some(include_str!(concat!("res/", $template)))
                }
            ) ),*
        ];

        /// List of extra templates used by other templates
        static EXTRA_TEMPLATES: [(&'static str, Option<&'static str>); count!( $( $( $extra_template )* )? )] = [
            $( $( (
                $extra_template,
                if cfg!(feature = "dev") {
                    None
                } else {
                    Some(include_str!(concat!("res/", $extra_template)))
                }
            ) ),* )?
        ];

        impl Templates {
            $(
                $(#[$attr])?
                pub async fn $name
                    $(< $( $lt $( : $clt $(+ $dlt )* )? ),+ >)?
                    (&self, context: &$param)
                -> Result<String, TemplateError> {
                    let ctx = Context::from_serialize(context)
                        .map_err(|source| TemplateError::Context { template: $template, source })?;

                    self.tera.read().await.render($template, &ctx)
                        .map_err(|source| TemplateError::Render { template: $template, source })
                }
            )*
        }

        /// Helps rendering each template with sample data
        pub mod check {
            use super::*;

            $(
                #[doc = concat!("Render the `", $template, "` template with sample contexts")]
                pub async fn $name
                    $(< $( $lt $( : $clt $(+ $dlt )* + TemplateContext )? ),+ >)?
                    (templates: &Templates)
                -> anyhow::Result<()> {
                    let samples: Vec< $param > = TemplateContext::sample();

                    let name = $template;
                    for sample in samples {
                        let context = serde_json::to_value(&sample)?;
                        ::tracing::info!(name, %context, "Rendering template");
                        templates. $name (&sample)
                            .await
                            .with_context(|| format!("Failed to render template {:?} with context {}", name, context))?;
                    }

                    Ok(())
                }
            )*
        }
    };
}
