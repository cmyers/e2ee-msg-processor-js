import { init as olmInit } from 'olm';
import { EncryptedMessage, MessageManager, SessionManager } from './olm-omemo';
import chalk from 'chalk';

(async () => {
    await olmInit();
    const aliceSessionManager = new SessionManager('alice', 'alice');
    const aliceMsgManager = new MessageManager(aliceSessionManager);

    const bobSessionManager = new SessionManager('bob', 'bob');
    const bobMsgManager = new MessageManager(bobSessionManager);

    const bob2SessionManager = new SessionManager('bob', 'bob2');
    const bob2MsgManager = new MessageManager(bob2SessionManager);

    const charlieSessionManager = new SessionManager('charlie', 'charlie');
    const charlieMsgManager = new MessageManager(charlieSessionManager);

    //session init

    // TODO deal with bundles in terms of devices per user. User can have multiple devices, therefore multiple bundles.
    // TODO!! get devicelist for recipient first, then a bundle for each device id to send messages to.
    const bobsBundle = bobSessionManager.generatePreKeyBundle();
    console.log(chalk.rgb(255, 191, 0)(`Alice gets Bob's bundle: ${JSON.stringify(bobsBundle)}`));

    const bob2sBundle = bob2SessionManager.generatePreKeyBundle();
    console.log(chalk.rgb(255, 191, 0)(`Alice gets Bob2's bundle: ${JSON.stringify(bob2sBundle)}`));

    if (!aliceSessionManager.session('bob', bobsBundle.deviceId)) {
        await aliceSessionManager.initialiseOutboundSession('bob', bobsBundle);
        await aliceSessionManager.initialiseOutboundSession('bob', bob2sBundle);
        const initialMessage = await aliceMsgManager.encryptMessage('bob', '');

        //bob receives key exchange
        //console.log(JSON.parse(bobSessionManager.Account.one_time_keys()).curve25519);
        await bobMsgManager.processMessage(initialMessage as EncryptedMessage);
        await bob2MsgManager.processMessage(initialMessage as EncryptedMessage);
        //console.log(JSON.parse(bobSessionManager.Account.one_time_keys()).curve25519);
    }

    const charliesBundle = charlieSessionManager.generatePreKeyBundle();
    console.log(chalk.rgb(255, 191, 0)(`Alice gets Charlie's bundle: ${JSON.stringify(charliesBundle)}`));

    if (!aliceSessionManager.session('charlie', charliesBundle.deviceId)) {
        await aliceSessionManager.initialiseOutboundSession('charlie', charliesBundle);
        const initialMessage = await aliceMsgManager.encryptMessage('charlie', '');

        //charlie receives key exchange
        await charlieMsgManager.processMessage(initialMessage as EncryptedMessage);
    }

    let aliceCounter = 0;
    let bobCounter = 0;
    let charlieCounter = 0;

    setInterval(async () => {
        let toSend = `messageToBobFromAlice${aliceCounter++}`;

        console.log(chalk.red(`alice Encrypts: ${toSend}`));
        let encryptedMessage = await aliceMsgManager.encryptMessage('bob', toSend);

        let plaintext = null;
        //bob receives first proper message after key exchange
        console.log(chalk.rgb(255, 191, 0)(`bob receives from alice: ${JSON.stringify(encryptedMessage)}`));
        plaintext = await bobMsgManager.processMessage(encryptedMessage);

        console.log(chalk.green(`bob Decrypts: ${plaintext}`));
        toSend = `messageToAliceFromBob${bobCounter++}`;

        console.log(chalk.rgb(255, 191, 0)(`bob2 receives from alice: ${JSON.stringify(encryptedMessage)}`));
        plaintext = await bob2MsgManager.processMessage(encryptedMessage);

        console.log(chalk.green(`bob2 Decrypts: ${plaintext}`));

        encryptedMessage = await bobMsgManager.encryptMessage('alice', toSend);
        console.log(chalk.red(`bob Encrypts: ${toSend}`));

        console.log(chalk.rgb(255, 191, 0)(`alice receives from bob: ${JSON.stringify(encryptedMessage)}`));
        plaintext = await aliceMsgManager.processMessage(encryptedMessage);
        console.log(chalk.green(`Alice Decrypts: ${plaintext}`));

        toSend = `messageToCharlieFromAlice${aliceCounter++}`;

        console.log(chalk.red(`alice Encrypts: ${toSend}`));
        encryptedMessage = await aliceMsgManager.encryptMessage('charlie', toSend);
        //bob receives first proper message after key exchange
        console.log(chalk.rgb(255, 191, 0)(`charlie receives from alice: ${JSON.stringify(encryptedMessage)}`));
        plaintext = await charlieMsgManager.processMessage(encryptedMessage);

        console.log(chalk.green(`charlie Decrypts: ${plaintext}`));

        if(aliceCounter%5 === 0) {
            toSend = `messageToAliceFromCharlie${charlieCounter++}`;

            encryptedMessage = await charlieMsgManager.encryptMessage('alice', toSend);
            console.log(chalk.red(`charlie Encrypts: ${toSend}`));

            console.log(chalk.rgb(255, 191, 0)(`alice receives from charlie: ${JSON.stringify(encryptedMessage)}`));
            plaintext = await aliceMsgManager.processMessage(encryptedMessage);
            console.log(chalk.green(`Alice Decrypts: ${plaintext}`));

            toSend = `messageToAliceFromBob2-${bobCounter++}`;

            encryptedMessage = await bob2MsgManager.encryptMessage('alice', toSend);
            console.log(chalk.red(`bob2 Encrypts: ${toSend}`));

            console.log(chalk.rgb(255, 191, 0)(`alice receives from bob2: ${JSON.stringify(encryptedMessage)}`));
            plaintext = await aliceMsgManager.processMessage(encryptedMessage);
            console.log(chalk.green(`Alice Decrypts: ${plaintext}`));
        }

    }, 2000);

})();