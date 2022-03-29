export const SUPERUSER: Superuser = "*"
export type Superuser = "*" // maximum ability


// TYPE CHECKS


export function isSuperuser(obj: unknown): obj is Superuser {
  return obj === SUPERUSER
}