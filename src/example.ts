import { init as olmInit } from '@matrix-org/olm';
import { EncryptedMessage } from './MessageProcessor';
import chalk from 'chalk';
//import { SessionManager } from './SessionManager';
import { OmemoManager } from './OmemoManager';

(async () => {
    await olmInit();

    const aliceOmemoManager = new OmemoManager('alice', 'aliceStore');
    const alicesBundle = aliceOmemoManager.generateBundle();
    const alice2OmemoManager = new OmemoManager('alice', 'aliceStore2');

    alice2OmemoManager.onDecryptFailed(async (jid: string) => {
        //TODO establish a new session and request resend of failed message
        console.log('OH SNAP!');
        alice2OmemoManager.processDevices(jid, [alicesBundle]);
        const initialMessage = await alice2OmemoManager.encryptMessage(jid, '');

        await aliceOmemoManager.decryptMessage(initialMessage as EncryptedMessage);
        //acknowledge session sucesss
        const acknowledgement = await aliceOmemoManager.encryptMessage(jid, 'Success');
        await alice2OmemoManager.decryptMessage(acknowledgement);
        
    })

    const bobOmemoManager = new OmemoManager('bob', 'bobStore');
    const bob2OmemoManager = new OmemoManager('bob', 'bobStore2');

    //const charlieSessionManager = new SessionManager('charlie', 'charlie');
    //const charlieMsgManager = new MessageProcessor(charlieSessionManager);

    console.log(chalk.rgb(255, 191, 0)(`Alice gets Bob's deviceIds: ${JSON.stringify([bobOmemoManager.getDeviceId(), bobOmemoManager.getDeviceId()])}`));
    
    const bobsBundle = bobOmemoManager.generateBundle();
    console.log(chalk.rgb(255, 191, 0)(`Alice gets Bob's bundle: ${JSON.stringify(bobsBundle)}`));

    const bob2sBundle = bob2OmemoManager.generateBundle();
    console.log(chalk.rgb(255, 191, 0)(`Alice gets Bob2's bundle: ${JSON.stringify(bob2sBundle)}`));

    console.log(chalk.rgb(255, 191, 0)(`Alice gets Alice's deviceIds: ${JSON.stringify([ alice2OmemoManager.getDeviceId()])}`));

    const alice2sBundle =  alice2OmemoManager.generateBundle();
    console.log(chalk.rgb(255, 191, 0)(`Alice gets Alice2's bundle: ${JSON.stringify(alice2sBundle)}`));  

    //console.log(chalk.rgb(255, 191, 0)(`Alice gets Charlie's deviceIds: ${JSON.stringify([charlieSessionManager.DeviceId])}`));

    //const charliesBundle = charlieSessionManager.generatePreKeyBundle();
    //console.log(chalk.rgb(255, 191, 0)(`Alice gets Charlie's bundle: ${JSON.stringify(charliesBundle)}`));

    console.log(chalk.rgb(255, 191, 0)(`Bob gets Bob's deviceIds: ${JSON.stringify([bob2OmemoManager.getDeviceId()])}`));

    if (!aliceOmemoManager.hasSession('alice', alice2sBundle.deviceId)) {
        aliceOmemoManager.processDevices('alice', [alice2sBundle]);
        const initialMessage = await aliceOmemoManager.encryptMessage('alice', '');

        await alice2OmemoManager.decryptMessage(initialMessage as EncryptedMessage);
        //acknowledge session sucesss
        const acknowledgement = await alice2OmemoManager.encryptMessage('alice', 'Success');
        await aliceOmemoManager.decryptMessage(acknowledgement);
    }

    if (!bobOmemoManager.hasSession('bob', bob2sBundle.deviceId)) {
        bobOmemoManager.processDevices('bob', [bob2sBundle]);
        const initialMessage = await bobOmemoManager.encryptMessage('bob', '');
        await bob2OmemoManager.decryptMessage(initialMessage as EncryptedMessage);

        //acknowledge session sucesss
        const acknowledgement = await bob2OmemoManager.encryptMessage('bob', 'Success');
        await bobOmemoManager.decryptMessage(acknowledgement);
    }

    if (!aliceOmemoManager.hasSession('bob', bobsBundle.deviceId)) {
        aliceOmemoManager.processDevices('bob', [bobsBundle, bob2sBundle]);
        const initialMessage = await aliceOmemoManager.encryptMessage('bob', '');

        await bobOmemoManager.decryptMessage(initialMessage as EncryptedMessage);
        await bob2OmemoManager.decryptMessage(initialMessage as EncryptedMessage);
        
        //acknowledge session sucesss
        let acknowledgement = await bobOmemoManager.encryptMessage('alice', 'Success');
        await aliceOmemoManager.decryptMessage(acknowledgement);
        await alice2OmemoManager.decryptMessage(acknowledgement);

        //acknowledge session sucesss
        acknowledgement = await bob2OmemoManager.encryptMessage('alice', 'Success');
        await aliceOmemoManager.decryptMessage(acknowledgement);
        await alice2OmemoManager.decryptMessage(acknowledgement);
    }

    // if (!aliceOmemoManager.hasSession(charlieSessionManager.JID,charliesBundle.deviceId)) {
    //     aliceOmemoManager.processDevices('charlie', [charliesBundle]);
    //     const initialMessage = await aliceOmemoManager.encryptMessage('charlie', '');

    //     await charlieMsgManager.processMessage(initialMessage as EncryptedMessage);
    //     charlieSessionManager.updateDeviceIds('alice', [aliceOmemoManager.getDeviceId(),  alice2OmemoManager.getDeviceId()]);
    //     //acknowledge session sucesss
    //     const acknowledgement = await charlieMsgManager.encryptMessage('alice', 'Success');
    //     await aliceOmemoManager.decryptMessage(acknowledgement);
    //     await alice2OmemoManager.decryptMessage(acknowledgement);
    // }

    let aliceCounter = parseInt(aliceOmemoManager.getValue('messagesSent')!);
    if(isNaN(aliceCounter)) {
        aliceCounter = 0;
    }

    let bobCounter = parseInt(bobOmemoManager.getValue('messagesSent')!);
    if(isNaN(bobCounter)) {
        bobCounter = 0;
    }

    //let charlieCounter = parseInt(charlieSessionManager.Store.get('messagesSent')!);
    //if(isNaN(charlieCounter)) {
    //    charlieCounter = 0;
    //}

    setInterval(async () => {
        let toSend = `messageToBobFromAlice${aliceCounter++}`;

        console.log(chalk.red(`alice Encrypts: ${toSend}`));
        let encryptedMessage = await aliceOmemoManager.encryptMessage('bob', toSend);
        aliceOmemoManager.setValue('messagesSent', aliceCounter);

        let plaintext = null;
        console.log(chalk.rgb(255, 191, 0)(`alice2 receives from alice: ${JSON.stringify(encryptedMessage)}`));
        plaintext = await alice2OmemoManager.decryptMessage(encryptedMessage);
        console.log(chalk.green(`alice2 Decrypts: ${plaintext}`));

        console.log(chalk.rgb(255, 191, 0)(`bob receives from alice: ${JSON.stringify(encryptedMessage)}`));
        plaintext = await bobOmemoManager.decryptMessage(encryptedMessage);

        console.log(chalk.green(`bob Decrypts: ${plaintext}`));

        console.log(chalk.rgb(255, 191, 0)(`bob2 receives from alice: ${JSON.stringify(encryptedMessage)}`));
        plaintext = await bob2OmemoManager.decryptMessage(encryptedMessage);

        console.log(chalk.green(`bob2 Decrypts: ${plaintext}`));

        // toSend = `messageToCharlieFromAlice${aliceCounter++}`;
        // console.log(chalk.red(`alice Encrypts: ${toSend}`));
        // encryptedMessage = await aliceOmemoManager.encryptMessage('charlie', toSend);
        // aliceOmemoManager.set('messagesSent', aliceCounter);

        // plaintext = null;
        // console.log(chalk.rgb(255, 191, 0)(`charlie receives from alice: ${JSON.stringify(encryptedMessage)}`));
        // plaintext = await charlieMsgManager.processMessage(encryptedMessage);
        // console.log(chalk.green(`charlie Decrypts: ${plaintext}`));

        // console.log(chalk.rgb(255, 191, 0)(`alice2 receives from alice: ${JSON.stringify(encryptedMessage)}`));
        // plaintext = await alice2OmemoManager.decryptMessage(encryptedMessage);
        // console.log(chalk.green(`alice2 Decrypts: ${plaintext}`));

        if (!bobOmemoManager.hasSession('alice', alice2sBundle.deviceId)) {
            bobOmemoManager.processDevices('alice', [alicesBundle, alice2sBundle]);
            const initialMessage = await bobOmemoManager.encryptMessage('alice', '');

            await aliceOmemoManager.decryptMessage(initialMessage as EncryptedMessage);
            await alice2OmemoManager.decryptMessage(initialMessage as EncryptedMessage);
            await bob2OmemoManager.decryptMessage(initialMessage as EncryptedMessage);

            //acknowledge session sucesss
            let acknowledgement = await aliceOmemoManager.encryptMessage('bob', 'Success');
            await alice2OmemoManager.decryptMessage(acknowledgement);
            await bobOmemoManager.decryptMessage(acknowledgement);
            await bob2OmemoManager.decryptMessage(acknowledgement);
            
            //acknowledge session sucesss
            acknowledgement = await alice2OmemoManager.encryptMessage('bob', 'Success');
            await aliceOmemoManager.decryptMessage(acknowledgement);
            await bobOmemoManager.decryptMessage(acknowledgement);
            await bob2OmemoManager.decryptMessage(acknowledgement);

            //acknowledge session sucesss
            acknowledgement = await bob2OmemoManager.encryptMessage('bob', 'Success');
            await aliceOmemoManager.decryptMessage(acknowledgement);
            await alice2OmemoManager.decryptMessage(acknowledgement);
            await bobOmemoManager.decryptMessage(acknowledgement);
        }

        // if (!charlieSessionManager.getSession('alice', alice2sBundle.deviceId)) {
        //     await charlieSessionManager.initialiseOutboundSession('alice', alice2sBundle);
        //     const initialMessage = await charlieMsgManager.encryptMessage('alice', '');
        //     await alice2OmemoManager.decryptMessage(initialMessage as EncryptedMessage);
        //     //acknowledge session sucesss
        //     const acknowledgement = await charlieMsgManager.encryptMessage('alice', 'Success');
        //     await aliceOmemoManager.decryptMessage(acknowledgement);
        //     await alice2OmemoManager.decryptMessage(acknowledgement);
        // }

        toSend = `messageToAliceFromBob${bobCounter++}`;

        console.log(chalk.red(`bob Encrypts: ${toSend}`));
        encryptedMessage = await bobOmemoManager.encryptMessage('alice', toSend);
        bobOmemoManager.setValue('messagesSent', bobCounter);

        plaintext = null;
        console.log(chalk.rgb(255, 191, 0)(`alice receives from bob: ${JSON.stringify(encryptedMessage)}`));
        plaintext = await aliceOmemoManager.decryptMessage(encryptedMessage);
        console.log(chalk.green(`alice Decrypts: ${plaintext}`));

        console.log(chalk.rgb(255, 191, 0)(`alice2 receives from bob: ${JSON.stringify(encryptedMessage)}`));
        plaintext = await alice2OmemoManager.decryptMessage(encryptedMessage);
        console.log(chalk.green(`alice2 Decrypts: ${plaintext}`));

        console.log(chalk.rgb(255, 191, 0)(`bob2 receives from bob: ${JSON.stringify(encryptedMessage)}`));
        plaintext = await bob2OmemoManager.decryptMessage(encryptedMessage);
        console.log(chalk.green(`bob2 Decrypts: ${plaintext}`));

        // if(aliceCounter%5 === 0) {
        //     toSend = `messageToAliceFromCharlie${charlieCounter++}`;

        //     encryptedMessage = await charlieMsgManager.encryptMessage('alice', toSend);
        //     charlieSessionManager.Store.set('messagesSent', charlieCounter);
        //     console.log(chalk.red(`charlie Encrypts: ${toSend}`));

        //     console.log(chalk.rgb(255, 191, 0)(`alice receives from charlie: ${JSON.stringify(encryptedMessage)}`));
        //     plaintext = await aliceOmemoManager.decryptMessage(encryptedMessage);
        //     console.log(chalk.green(`alice Decrypts: ${plaintext}`));

        //     console.log(chalk.rgb(255, 191, 0)(`alice2 receives from charlie: ${JSON.stringify(encryptedMessage)}`));
        //     plaintext = await alice2OmemoManager.decryptMessage(encryptedMessage);
        //     console.log(chalk.green(`alice2 Decrypts: ${plaintext}`));
        // }

    }, 2000);

})();