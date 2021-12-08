import EdKey from "../src/keypair/ed25519"


/** did:key:z6MkfWSvKVrqhmuqGReBD5CTrhJ1us4cRQmasX9rjD1MS8u7 */
export const alice = EdKey.fromSecretKey("t0rXPzUXY9lDyrIf1y96e1/hToGe/t0hBPxZdMp9NWwPrLmvmuQ0fw7vWvZfT5W9mRJKN1hW7+YrY+pAqk8X8g==")

/** did:key:z6MkubmiZt73SiAFffHpFcmGxYce2JoFMiUbpev5TuYYFRu6 */
export const bob = EdKey.fromSecretKey("w/X3iLRv+NZmDbs1ZOyOHVcAwJTN4Gw0lRW5jOB832ThDYAoRQ3Cs5/OoMpuuXedg64tTt63C+3n/UMR5l+QrQ==")

/** did:key:z6MkeaLWTPzwVDm2KAgSeUBuEpHfHJTYts5wGaz2srVwZ1Mz */
export const mallory = EdKey.fromSecretKey("IxS23xpPSV5Ae7tYpjVOMBAaM7SNGNBEsOLp7CUVFdMB0By5QJILOgVvSGFUzht1P8TteLd8ZOK+cLq0fexu4Q==")


export function didToName(did: string) {
    if (did === alice.did()) return "alice"
    if (did === bob.did()) return "bob"
    if (did === mallory.did()) return "mallory"
    return did
}
