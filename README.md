# e2ee-msg-processor-js
 <a href="https://www.npmjs.com/package/e2ee-msg-processor-js"><img src="https://img.shields.io/npm/v/e2ee-msg-processor-js" /></a>

End to end encryption message processor which can be used to encrypt messages between two devices over any message protocol.

It uses Matrix Olm (https://matrix.org/docs/projects/other/olm) which is an implementation of the Double Ratchet Algorithm to handle session creation and key exchange.

The key exchange and message format is based on the OMEMO protocol, but doesn't require XMPP as the transmission medium. The message format is simply json and can be sent as the developer sees fit.

Here's a contrived example simulating sending a message between Alice and Bob:

```
import { LocalStorage } from 'node-localstorage';
import { OmemoManager } from 'e2ee-msg-processor-js';

(async () => {
    await OmemoManager.init();

    const aliceLocalStorage = new LocalStorage('./local_storage/aliceStore');
    const aliceOmemoManager = new OmemoManager('alice', aliceLocalStorage);

    const bobLocalStorage = new LocalStorage('./local_storage/bobStore');
    const bobOmemoManager = new OmemoManager('bob', bobLocalStorage);
    const bobsBundle = bobOmemoManager.generateBundle();

    aliceOmemoManager.processDevices('bob', [bobsBundle]);
    const aliceToBobMessage = await aliceOmemoManager.encryptMessage('bob', 'To Bob from Alice');
    const aliceDecrypted = await bobOmemoManager.decryptMessage(aliceToBobMessage);
    console.log(aliceDecrypted);
    
    const bobToAliceMessage = await bobOmemoManager.encryptMessage('alice', 'To Alice from Bob');
    const bobDecrypted = await aliceOmemoManager.decryptMessage(bobToAliceMessage);
    console.log(bobDecrypted);

})();
```
WARNING: I don't claim this to be cryptographically safe by any means. Please if you're a cryptography researcher then by all means try and break this and submit an issue here.

Furthermore this is still experimental and littered with console.logs for debugging. This is to be improved with a debug flag in due course.
