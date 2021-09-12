# e2ee-msg-processor-js
 <a href="https://www.npmjs.com/package/e2ee-msg-processor-js"><img src="https://img.shields.io/npm/v/e2ee-msg-processor-js" /></a>

End to end encryption message processor which can be used to encrypt messages between two or more devices running on any platform and sent over any messaging protocol.

It uses an external library for the implementation of the Double Ratchet Algorithm to handle session creation and key exchange (https://matrix.org/docs/projects/other/olm).

The key exchange and message format is loosely based on the OMEMO protocol which utilises 128 bit AES-GCM. Although OMEMO is an extension of the XMPP protocol, it doesn't require XMPP as the transmission medium. The message format is output as json and can be reconfigured for transmittion at the developer's descretion.

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

WARNING: THIS LIBRARY IS UNTESTED AND THEREFORE INSECURE. USE AT YOUR OWN RISK...

Please if you're a cryptography researcher then by all means try and break this and submit an issue here.
