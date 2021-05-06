import * as libsignal from '@privacyresearch/libsignal-protocol-typescript'
import { DeviceType, SessionCipher } from '@privacyresearch/libsignal-protocol-typescript';
import { SignalProtocolStore, } from './store/store';
import chalk from 'chalk';
import { decryptMessage, encryptMessage, generateIdentity, generatePreKeyBundle } from './omemo';


(async () => {
    const aliceStore = new SignalProtocolStore("alice_localhost");
    const bobStore = new SignalProtocolStore("bob_localhost");

    const hasSession = aliceStore.containsKey('session') && bobStore.containsKey('session');

    let aliceCounter = 0;
    let bobCounter = 0;

    let aliceSessionCipher: libsignal.SessionCipher;
    let bobSessionCipher: libsignal.SessionCipher;

    if (hasSession) {
        const ALICE_ADDRESS = new libsignal.SignalProtocolAddress("alice@localhost", aliceStore.get('registrationId'));
        const BOB_ADDRESS = new libsignal.SignalProtocolAddress("bob@localhost", bobStore.get('registrationId'));

        console.log(chalk.cyan(`${ALICE_ADDRESS.getName()} has a session with ${BOB_ADDRESS.getName()}`));

        aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
        bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);
    } else {
        await generateIdentity(aliceStore);
        await generateIdentity(bobStore);

        const ALICE_ADDRESS = new libsignal.SignalProtocolAddress("alice@localhost", aliceStore.get('registrationId'));
        const BOB_ADDRESS = new libsignal.SignalProtocolAddress("bob@localhost", bobStore.get('registrationId'));

        const preKeyBundle = await generatePreKeyBundle(bobStore);

        var builder = new libsignal.SessionBuilder(aliceStore, BOB_ADDRESS);
        await builder.processPreKey(preKeyBundle as DeviceType<ArrayBuffer>);

        aliceSessionCipher = new libsignal.SessionCipher(aliceStore, BOB_ADDRESS);
        bobSessionCipher = new libsignal.SessionCipher(bobStore, ALICE_ADDRESS);
    }

    const aliceDeviceId = await aliceSessionCipher.storage.getLocalRegistrationId() as number;
    const bobDeviceId = await bobSessionCipher.storage.getLocalRegistrationId() as number;


    setInterval(async () => {
        const toSend = `messageToBobFromAlice${aliceCounter++}`;
        const encryptedMessage = await encryptMessage(aliceSessionCipher, toSend);

        console.log(chalk.red(`Alice Encrypts: ${toSend}`));
        let plaintext = null;

        console.log(chalk.red(`Bob receives: ${JSON.stringify(encryptedMessage)}`));

        if (encryptedMessage.rid !== bobDeviceId || encryptedMessage.jid !== 'bob@localhost') {
            throw new Error('Message not intended for bob@localhost!');
        }

        plaintext = await decryptMessage(bobSessionCipher, encryptedMessage);

        if (plaintext !== null) {
            console.log(chalk.green(`Bob Decrypts: ${plaintext}`));

            const toSend = `messageToAliceFromBob${bobCounter++}`;
            const encryptedMessage = await encryptMessage(bobSessionCipher, toSend);
            console.log(chalk.red(`Bob Encrypts: ${toSend}`));

            plaintext = null;

            console.log(chalk.red(`Alice receives: ${JSON.stringify(encryptedMessage)}`));

            if (encryptedMessage.rid !== aliceDeviceId || encryptedMessage.jid !== 'alice@localhost') {
                throw new Error('Message not intended for alice@localhost!');
            }

            plaintext = await decryptMessage(aliceSessionCipher, encryptedMessage);


            if (plaintext !== null) {
                console.log(chalk.green(`Alice Decrypts: ${plaintext}`));
            }
        }
    }, 2000);
})();