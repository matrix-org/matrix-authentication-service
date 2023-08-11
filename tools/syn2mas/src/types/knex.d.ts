import "knex/types/result";

declare module "knex/types/result" {
  interface Registry {
      Count: number;
  }
}
