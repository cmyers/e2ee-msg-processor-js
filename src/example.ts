import { init as olmInit } from 'olm';
import { EncryptedMessage, MessageManager } from './MessageManager';
import chalk from 'chalk';
import { SessionManager } from './SessionManager';

(async () => {
    await olmInit();
    const aliceSessionManager = new SessionManager('alice', 'alice');
    const aliceMsgManager = new MessageManager(aliceSessionManager);

    const alice2SessionManager = new SessionManager('alice', 'alice2');
    const alice2MsgManager = new MessageManager(alice2SessionManager);

    const bobSessionManager = new SessionManager('bob', 'bob');
    const bobMsgManager = new MessageManager(bobSessionManager);

    const bob2SessionManager = new SessionManager('bob', 'bob2');
    const bob2MsgManager = new MessageManager(bob2SessionManager);

    console.log(chalk.rgb(255, 191, 0)(`Alice gets Bob's deviceIds: ${JSON.stringify([bobSessionManager.DeviceId, bob2SessionManager.DeviceId])}`));
    aliceSessionManager.updateDeviceIds(bobSessionManager.JID, [bobSessionManager.DeviceId, bob2SessionManager.DeviceId]);

    const bobsBundle = bobSessionManager.generatePreKeyBundle();
    console.log(chalk.rgb(255, 191, 0)(`Alice gets Bob's bundle: ${JSON.stringify(bobsBundle)}`));

    const bob2sBundle = bob2SessionManager.generatePreKeyBundle();
    console.log(chalk.rgb(255, 191, 0)(`Alice gets Bob2's bundle: ${JSON.stringify(bob2sBundle)}`));

    console.log(chalk.rgb(255, 191, 0)(`Alice gets Alice's deviceIds: ${JSON.stringify([alice2SessionManager.DeviceId])}`));
    aliceSessionManager.updateDeviceIds(alice2SessionManager.JID, [alice2SessionManager.DeviceId]);

    const alice2sBundle = alice2SessionManager.generatePreKeyBundle();
    console.log(chalk.rgb(255, 191, 0)(`Alice gets Alice2's bundle: ${JSON.stringify(alice2sBundle)}`));

    console.log(chalk.rgb(255, 191, 0)(`Bob gets Bob's deviceIds: ${JSON.stringify([bob2SessionManager.DeviceId])}`));
    bobSessionManager.updateDeviceIds(bob2SessionManager.JID, [bob2SessionManager.DeviceId]);

    if (!aliceSessionManager.session(alice2SessionManager.JID, alice2sBundle.deviceId)) {
        await aliceSessionManager.initialiseOutboundSession(alice2SessionManager.JID, alice2sBundle);
        const initialMessage = await aliceMsgManager.encryptMessage(alice2SessionManager.JID, '');

        await alice2MsgManager.processMessage(initialMessage as EncryptedMessage);
    }

    if (!bobSessionManager.session(bob2SessionManager.JID, bob2sBundle.deviceId)) {
        await bobSessionManager.initialiseOutboundSession(bob2SessionManager.JID, bob2sBundle);
        const initialMessage = await bobMsgManager.encryptMessage(bob2SessionManager.JID, '');

        await bob2MsgManager.processMessage(initialMessage as EncryptedMessage);
    }

    if (!aliceSessionManager.session(bobSessionManager.JID, bobsBundle.deviceId)) {
        await aliceSessionManager.initialiseOutboundSession(bobSessionManager.JID, bobsBundle);
        await aliceSessionManager.initialiseOutboundSession(bob2SessionManager.JID, bob2sBundle);
        const initialMessage = await aliceMsgManager.encryptMessage('bob', '');

        await bobMsgManager.processMessage(initialMessage as EncryptedMessage);
        console.log(chalk.rgb(255, 191, 0)(`Bob gets Alice's deviceIds: ${JSON.stringify([aliceSessionManager.DeviceId, alice2SessionManager.DeviceId])}`));

        await bob2MsgManager.processMessage(initialMessage as EncryptedMessage);
        console.log(chalk.rgb(255, 191, 0)(`Bob2 gets Alice's deviceIds: ${JSON.stringify([aliceSessionManager.DeviceId, alice2SessionManager.DeviceId])}`));

    }

    bobSessionManager.updateDeviceIds(aliceSessionManager.JID, [aliceSessionManager.DeviceId, alice2SessionManager.DeviceId]);
    bob2SessionManager.updateDeviceIds(aliceSessionManager.JID, [aliceSessionManager.DeviceId, alice2SessionManager.DeviceId]);

    let aliceCounter = parseInt(aliceSessionManager.Store.get('messagesSent')!);
    if(isNaN(aliceCounter)) {
        aliceCounter = 0;
    }
    let bobCounter = parseInt(bobSessionManager.Store.get('messagesSent')!);
    if(isNaN(bobCounter)) {
        bobCounter = 0;
    }

    setInterval(async () => {
        let toSend = `messageToBobFromAlice${aliceCounter++}`;

        console.log(chalk.red(`alice Encrypts: ${toSend}`));
        let encryptedMessage = await aliceMsgManager.encryptMessage('bob', toSend);
        aliceSessionManager.Store.set('messagesSent', aliceCounter);

        let plaintext = null;
        console.log(chalk.rgb(255, 191, 0)(`alice2 receives from alice: ${JSON.stringify(encryptedMessage)}`));
        plaintext = await alice2MsgManager.processMessage(encryptedMessage);
        console.log(chalk.green(`alice2 Decrypts: ${plaintext}`));

        console.log(chalk.rgb(255, 191, 0)(`bob receives from alice: ${JSON.stringify(encryptedMessage)}`));
        plaintext = await bobMsgManager.processMessage(encryptedMessage);

        console.log(chalk.green(`bob Decrypts: ${plaintext}`));

        console.log(chalk.rgb(255, 191, 0)(`bob2 receives from alice: ${JSON.stringify(encryptedMessage)}`));
        plaintext = await bob2MsgManager.processMessage(encryptedMessage);

        console.log(chalk.green(`bob2 Decrypts: ${plaintext}`));

        if (!bobSessionManager.session('alice', alice2sBundle.deviceId)) {
            await bobSessionManager.initialiseOutboundSession(alice2SessionManager.JID, alice2sBundle);
            const initialMessage = await bobMsgManager.encryptMessage(alice2SessionManager.JID, '');
            await alice2MsgManager.processMessage(initialMessage as EncryptedMessage);
        }

        if (!bobSessionManager.session(bobSessionManager.JID, bob2sBundle.deviceId)) {
            await bobSessionManager.initialiseOutboundSession(bob2SessionManager.JID, bob2sBundle);
            const initialMessage = await bobMsgManager.encryptMessage(bob2SessionManager.JID, '');
            await bob2MsgManager.processMessage(initialMessage as EncryptedMessage);
        }

        toSend = `messageToAliceFromBob${bobCounter++}`;

        console.log(chalk.red(`bob Encrypts: ${toSend}`));
        encryptedMessage = await bobMsgManager.encryptMessage('alice', toSend);
        bobSessionManager.Store.set('messagesSent', bobCounter);

        plaintext = null;
        console.log(chalk.rgb(255, 191, 0)(`alice receives from bob: ${JSON.stringify(encryptedMessage)}`));
        plaintext = await aliceMsgManager.processMessage(encryptedMessage);
        console.log(chalk.green(`alice Decrypts: ${plaintext}`));

        console.log(chalk.rgb(255, 191, 0)(`alice2 receives from bob: ${JSON.stringify(encryptedMessage)}`));
        plaintext = await alice2MsgManager.processMessage(encryptedMessage);
        console.log(chalk.green(`alice2 Decrypts: ${plaintext}`));

        console.log(chalk.rgb(255, 191, 0)(`bob2 receives from bob: ${JSON.stringify(encryptedMessage)}`));
        plaintext = await bob2MsgManager.processMessage(encryptedMessage);
        console.log(chalk.green(`bob2 Decrypts: ${plaintext}`));

    }, 2000);

})();