# e2ee-msg-processor-js
<a href="https://www.npmjs.com/package/e2ee-msg-processor-js"><img src="https://img.shields.io/npm/v/e2ee-msg-processor-js" /></a>

End to end encryption message processor which can be used to encrypt messages between two or more devices running on any platform and sent over any messaging protocol.

It uses an external library for the implementation of the Double Ratchet Algorithm to handle session creation and key exchange (https://matrix.org/docs/projects/other/olm).

The key exchange and message format is loosely based on the OMEMO protocol which utilises 128 bit AES-GCM. Although OMEMO is an extension of the XMPP protocol, it doesn't require XMPP as the transmission medium. The message format is output as json and can be reconfigured for transmission at the developer's descretion.

The LocalStorage interface will need implementing in order to provide a means of storing the sessions. In the example below we've used node-localstorage which is sufficent for our needs, however other situations may require a different storage mechanism so the implementation is left to the developer.

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
    //bundle and device id need to be published via XMPP pubsub, or an equivalent service so that they are available for Alice and other clients devices wishing to communicate with Bob
    const bobsBundle = bobOmemoManager.generateBundle();

    aliceOmemoManager.processDevices('bob', [bobsBundle]);
    //This message object can be mapped to an XMPP send query or just sent as JSON over TLS or some other secure channel.
    const aliceToBobMessage = await aliceOmemoManager.encryptMessage('bob', 'To Bob from Alice');

    //Bob will then receive the message and process it
    const aliceDecrypted = await bobOmemoManager.decryptMessage(aliceToBobMessage);
    console.log(aliceDecrypted);
    
    //Bob can then reply without the need for a key bundle from Alice
    const bobToAliceMessage = await bobOmemoManager.encryptMessage('alice', 'To Alice from Bob');
    const bobDecrypted = await aliceOmemoManager.decryptMessage(bobToAliceMessage);
    console.log(bobDecrypted);

})();
```

WARNING: THIS LIBRARY IS UNTESTED AND THEREFORE INSECURE. USE AT YOUR OWN RISK.

If you're a cryptography researcher then please by all means try and break this and submit an issue or a PR.
