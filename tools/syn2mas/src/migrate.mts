import { readFile } from "node:fs/promises";
import { parse } from "ts-command-line-args";
import id128 from "id128";
import log4js from "log4js";
import yaml from "yaml";

import { SUser } from "./types/SUser";
import { SUserThreePid } from "./types/SUserThreePid";
import { MUserPassword } from "./types/MUserPassword";
import { MUserEmail } from "./types/MUserEmail";
import { SUserExternalId } from "./types/SUserExternalId";
import { SAccessToken } from "./types/SAccessToken";
import { SRefreshToken } from "./types/SRefreshToken";
import { MCompatAccessToken } from "./types/MCompatAccessToken";
import { MCompatRefreshToken } from "./types/MCompatRefreshToken";
import { MCompatSession } from "./types/MCompatSession";
import { MUpstreamOauthLink } from "./types/MUpstreamOauthLink";
import { MUpstreamOauthProvider } from "./types/MUpstreamOauthProvider";
import { UUID } from "./types";
import { SynapseConfig } from "./types/SynapseConfig";
import { MASConfig } from "./types/MASConfig";
import { connectToSynapseDatabase, connectToMASDatabase } from "./db.mjs";

const log = log4js.getLogger("migrate");

interface MigrationOptions {
  command: string;
  synapseConfigFile: string;
  masConfigFile: string;
  upstreamProviderMapping: string[];
  dryRun?: boolean;
  help?: boolean;
}

export async function migrate(argv?: string[]): Promise<void> {
  const args = parse<MigrationOptions>({
    command: { type: String, description: "Command to run", defaultOption: true, typeLabel: "migrate" },
    synapseConfigFile: { type: String, description: "Path to synapse homeserver.yaml config file" },
    masConfigFile: { type: String, description: "Path to MAS config.yaml" },
    upstreamProviderMapping: { type: String, defaultValue: [], multiple: true, description: "Mapping of upstream provider IDs to MAS provider IDs. Format: <upstream_provider_id>:<mas_provider_id>" },
    dryRun: { type: Boolean, optional: true, defaultValue: false },
    help: { type: Boolean, optional: true, alias: "h", description: "Prints this usage guide" },
  },
  {
    helpArg: "help",
    argv,
  });
  
  const warnings: string[] = [];
  function warn(message: string): void {
    warnings.push(message);
  }
  
  let fatals = 0;
  function fatal(message: string): void {
    log.fatal(message);
    warnings.forEach((w) => log.warn(w));
    if (!args.dryRun) {
      process.exit(1);
    }
    fatals += 1;
  }
  
  function makeUuid<T>(): UUID<T> {
    return id128.Uuid4.fromRaw(id128.UlidMonotonic.generate().toRaw()).toCanonical();
  }
  
  // load synapse config
  const synapseConfig: SynapseConfig = yaml.parse(await readFile(args.synapseConfigFile, "utf8"));
  
  // connect to synapse databases
  const synapse = connectToSynapseDatabase(synapseConfig);
  
  // load MAS config
  const masConfig: MASConfig = yaml.parse(await readFile(args.masConfigFile, "utf8"));
  
  if (!masConfig.database?.uri) {
    log.fatal("Missing database URI in MAS config");
    process.exit(1);
  }
  const mas = connectToMASDatabase(masConfig);
  
  const upstreamProviders = new Map<string, MUpstreamOauthProvider>();
  
  for (const mapping of args.upstreamProviderMapping) {
    const [providerId, masProviderId] = mapping.split(":");
    if (!id128.Uuid.isRaw(masProviderId) && !id128.Uuid.isCanonical(masProviderId)) {
      throw new Error(`Upstream provider mapping UUID is not in correct format. It should be a UUID: ${masProviderId}`);
    }
    log.info(`Loading existing upstream provider ${masProviderId} from MAS database as ${providerId}`);
    const existingProvider = await mas("upstream_oauth_providers").select("*").where({ upstream_oauth_provider_id: masProviderId }).first();
    if (!existingProvider) {
      throw new Error(`Could not find upstream provider ${masProviderId} in MAS database`);
    }
    upstreamProviders.set(providerId, existingProvider);
  }
  
  function stringifyAndRedact(input: any): string {
    const x = JSON.stringify(input);
  
    return x.replace(/("(password_hash|hashed_password|access_token|token)":")[^"]*"/, "$1redacted\"");
  }
  
  type Execution = (() => Promise<void>);
  
  const existingMasUsers = await mas.count({ count: "*" }).from("users").first();

  if (parseInt(`${existingMasUsers?.count ?? 0}`) > 0) {
    fatal(`Found ${existingMasUsers?.count} existing users in MAS. Refusing to continue. Please clean MAS and try again.`);
  }

  const synapseUsers = await synapse.select("*").from<SUser>("users");
  log.info(`Found ${synapseUsers.length} users in Synapse`);
  for (const user of synapseUsers) {
    const localpart = user.name.split(":")[0].substring(1);
    log.info(`Processing user ${user.name} as ${localpart}`);

    let warningsForUser = 0;
    const executions: Execution[] = [];

    if (user.deactivated === 1) {
      fatal(`Migration of deactivated users is not supported: ${user.name}`);
    }

    if (user.is_guest === 1) {
      fatal(`Migration of guest users is not supported: ${user.name}`);
    }

    // users => users
    const masUser = {
      user_id: makeUuid(),
      username: localpart,
      created_at: new Date(parseInt(`${user.creation_ts}`) * 1000),
    };
    executions.push(() => mas.insert(masUser!).into("users")); 
    log.debug(`${stringifyAndRedact(user)} => ${stringifyAndRedact(masUser)}`);
    // users.password_hash => user_passwords
    if (user.password_hash) {
        const masUserPassword: MUserPassword = {
          user_password_id: makeUuid(),
          user_id: masUser.user_id,
          hashed_password: user.password_hash,
          created_at: masUser.created_at, // TODO: should we use now() instead of created_at?
          version: 1,
        };

        log.debug(`Password ${user.password_hash.slice(-4)} => ${stringifyAndRedact(masUserPassword)}`);
        executions.push(() => mas.insert(masUserPassword).into("user_passwords"));
      }

      // user_threepids => user_emails
      let primaryEmail: MUserEmail | undefined;
      const synapseThreePids = await synapse.select("*").from<SUserThreePid>("user_threepids").where({ user_id: user.name });
      for (const threePid of synapseThreePids) {
        if (threePid.medium !== "email") {
          warningsForUser += 1;
          warn(`Skipping non-email 3pid ${threePid.medium} for user ${user.name}`);
          continue;
        }
        const masUserEmail: MUserEmail = {
          user_email_id: makeUuid(),
          user_id: masUser.user_id,
          email: threePid.address.toLowerCase(),
          created_at: new Date(parseInt(`${threePid.added_at}`) * 1000),
          confirmed_at: threePid.validated_at ? new Date(parseInt(`${threePid.validated_at}`) * 1000) : undefined,
        };

        log.debug(`${stringifyAndRedact(threePid)} => ${stringifyAndRedact(masUserEmail)}`);
        if (!primaryEmail && threePid.validated_at) {
          primaryEmail = masUserEmail;
        }
        executions.push(() => mas.insert(masUserEmail).into("user_emails"));
      }
      if (primaryEmail) {
        log.debug(`Setting primary email for existing user ${masUser.username} to ${primaryEmail.email} as update`);
        executions.push(() => mas("users").where({ user_id: masUser!.user_id }).update({ primary_user_email_id: primaryEmail!.user_email_id }));
      }

      // user_external_ids => upstream_oauth_links
      const synapseExternalIds = await synapse.select("*").from<SUserExternalId>("user_external_ids").where({ user_id: user.name });
      for (const externalId of synapseExternalIds) {
        try {
          if (!upstreamProviders.has(externalId.auth_provider)) {
            throw new Error(`Unknown upstream provider ${externalId.auth_provider}`);
          }
          const provider = upstreamProviders.get(externalId.auth_provider)!;
          const masUpstreamOauthLink: MUpstreamOauthLink = {
            upstream_oauth_link_id: makeUuid(),
            user_id: masUser.user_id,
            upstream_oauth_provider_id: provider.upstream_oauth_provider_id,
            subject: externalId.external_id,
            created_at: masUser.created_at,
          };
            
          log.debug(`${stringifyAndRedact(synapseExternalIds)} => ${stringifyAndRedact(masUpstreamOauthLink)}`);

          executions.push(() => mas.insert(masUpstreamOauthLink).into("upstream_oauth_links"));
        } catch (e) {
          fatal(`Failed to import external id ${externalId.external_id} with ${externalId.auth_provider} for user ${user.name}: ${e}`);
        }
      }

      // access_tokens,refresh_tokens => compat_sessions,compat_access_tokens
      const synapseAccessTokens = await synapse.select("*").from<SAccessToken>("access_tokens").where({ user_id: user.name });
      for (const accessToken of synapseAccessTokens) {
        if (!accessToken.device_id) {
          warningsForUser += 1;
          warn(`Skipping access token ${accessToken.token} for user ${user.name} with no device_id`);
          continue;
        }

        const masCompatSession: MCompatSession = {
          compat_session_id: makeUuid(),
          user_id: masUser.user_id,
          device_id: accessToken.device_id,
          created_at: accessToken.last_validated ? new Date(parseInt(`${accessToken.last_validated}`)) : masUser.created_at,
          is_synapse_admin: user.admin === 1,
        };
        log.debug(`${stringifyAndRedact(accessToken)} => ${stringifyAndRedact(masCompatSession)}`);
        executions.push(() => mas.insert(masCompatSession).into("compat_sessions"));

        const masCompatAccessToken: MCompatAccessToken = {
          compat_access_token_id: makeUuid(),
          compat_session_id: masCompatSession.compat_session_id,
          access_token: accessToken.token,
          created_at: masCompatSession.created_at,
        };
        log.debug(`Access token ${accessToken.id} => ${stringifyAndRedact(masCompatAccessToken)}`);
        executions.push(() => mas.insert(masCompatAccessToken).into("compat_access_tokens"));

        if (accessToken.refresh_token_id) {
          const synapseRefreshToken = await synapse.select("*").from<SRefreshToken>("refresh_tokens").where({ id: accessToken.refresh_token_id }).first();
          if (synapseRefreshToken) {
            const masCompatRefreshToken: MCompatRefreshToken = {
              compat_refresh_token_id: makeUuid(),
              compat_session_id: masCompatSession.compat_session_id,
              compat_access_token_id: masCompatAccessToken.compat_access_token_id,
              refresh_token: synapseRefreshToken.token,
              created_at: masCompatSession.created_at,
            };
            log.debug(`Refresh token ${synapseRefreshToken.id} => ${stringifyAndRedact(masCompatRefreshToken)}`);
            executions.push(() => mas.insert(masCompatRefreshToken).into("compat_refresh_tokens"));
          } else {
            warningsForUser += 1;
            warn(`Unable to locate refresh token ${accessToken.refresh_token_id} for user ${user.name}`);
          }
        }
      }

    if (warningsForUser > 0) {
      if (!args.dryRun) {
        fatal(`User ${user.name} had ${warningsForUser} warnings`);
      } else {
        log.warn(`User ${user.name} had ${warningsForUser} warnings`);
      }
    } else if (!args.dryRun) {
      log.info(`Running ${executions.length} updates for user ${user.name}`);
      const tx = await mas.transaction();
      try {
        for (const execution of executions) {
          await execution();
        }
        await tx.commit();
        log.info(`Migrated user ${user.name}`);
      } catch (e) {
        try {
          await tx.rollback();
        } catch (e2) {
          log.error(`Failed to rollback transaction: ${e2}`);
        }
        throw e;
      }
    }
  }
  log.info(`Completed migration ${args.dryRun ? "dry-run " : ""}of ${synapseUsers.length} users with ${fatals} fatals and ${warnings.length} warnings:`);
  warnings.forEach((w) => log.warn(w));
  if (fatals > 0) {
    throw new Error(`Migration failed with ${fatals} fatals`);
  }
}
