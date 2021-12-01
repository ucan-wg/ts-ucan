import * as token from '../src/token'
import EdKey from '../src/keypair/ed25519'

describe('wnfs capability', () => {
  it('checks fine when delegated', async () => {
    const authLobby = await EdKey.create()
    const flatmateApp = await EdKey.create()
    const thirdApp = await EdKey.create()
    
    const authUCAN = await token.build({
      audience: flatmateApp.did(),
      issuer: authLobby,
      capabilities: [
        {
          "wnfs": "matheus23.fission.name/private/9744adf9bf75eec5799ae957722af15e",
          "cap": "OVERWRITE"
        },
        {
          "wnfs": "matheus23.fission.name/private/2f72d182696b8bb3aa1cf5118cbbedf0",
          "cap": "OVERWRITE"
        },
      ]
    })

    const thirdAppUCAN = await token.build({
        audience: thirdApp.did(),
        issuer: flatmateApp,
        capabilities: [
            {
              "wnfs": "matheus23.fission.name/private/6994750ac5a2833190a7484a93987f6f",
              "cap": "OVERWRITE"
            },
        ],
        proof: token.encode(authUCAN)
    })

    console.log(token.encode(thirdAppUCAN))
  })
})
