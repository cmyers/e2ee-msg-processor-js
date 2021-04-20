import * as libsignal from '@privacyresearch/libsignal-protocol-typescript'
import { DeviceType, KeyPairType } from '@privacyresearch/libsignal-protocol-typescript';
import { DataUtils, SignalProtocolStore, } from './store/store';
import chalk from 'chalk';

const KeyHelper = libsignal.KeyHelper;

function generateIdentity(store: SignalProtocolStore) {
    return Promise.all([
        KeyHelper.generateIdentityKeyPair(),
        KeyHelper.generateRegistrationId(),
    ]).then(function (result) {
        store.storeIdentityKeyPair(result[0]);
        store.storeLocalRegistrationId(result[1]);
    });
}

function generatePreKeyBundle(store: SignalProtocolStore, preKeyId: number, signedPreKeyId: number) {
    return Promise.all([
        store.getIdentityKeyPair(),
        store.getLocalRegistrationId()
    ]).then(function (result) {
        const identity = result[0] as KeyPairType<ArrayBuffer>;
        var registrationId = result[1];

        return Promise.all([
            KeyHelper.generatePreKey(preKeyId),
            KeyHelper.generateSignedPreKey(identity, signedPreKeyId),
        ]).then(function (keys) {
            var preKey = keys[0]
            var signedPreKey = keys[1];

            store.storePreKey(preKeyId, preKey.keyPair);
            store.storeSignedPreKey(signedPreKeyId, signedPreKey.keyPair);

            return {
                identityKey: identity.pubKey,
                registrationId: registrationId,
                preKey: {
                    keyId: preKeyId,
                    publicKey: preKey.keyPair.pubKey
                },
                signedPreKey: {
                    keyId: signedPreKeyId,
                    publicKey: signedPreKey.keyPair.pubKey,
                    signature: signedPreKey.signature
                }
            };
        });
    });
}

var ALICE_ADDRESS = new libsignal.SignalProtocolAddress("alice@localhost", KeyHelper.generateRegistrationId());
var BOB_ADDRESS = new libsignal.SignalProtocolAddress("bob@localhost", KeyHelper.generateRegistrationId());

var aliceStore = new SignalProtocolStore();
var bobStore = new SignalProtocolStore();

var bobPreKeyId = KeyHelper.generateRegistrationId();
var bobSignedKeyId = KeyHelper.generateRegistrationId();

Promise.all([
    generateIdentity(aliceStore),
    generateIdentity(bobStore),
]).then(function () {
    return generatePreKeyBundle(bobStore, bobPreKeyId, bobSignedKeyId);
}).then(function (preKeyBundle) {
    //go get Bob#s prekey bundle
    var builder = new libsignal.SessionBuilder(aliceStore, BOB_ADDRESS);
    let aliceCounter = 0;
    let bobCounter = 0;
    var process = builder.processPreKey(preKeyBundle as DeviceType<ArrayBuffer>);
    process.then(() => {
        var aliceSessionCipher = new libsignal.SessionCipher(aliceStore, BOB_ADDRESS);
        var bobSessionCipher = new libsignal.SessionCipher(bobStore, ALICE_ADDRESS);

        const toSend = `messageToBobFromAlice${aliceCounter++}`;
        console.log(chalk.red(`Alice Encrypts: ${toSend}`));
        aliceSessionCipher.encrypt(new TextEncoder().encode(`messageToBobFromAlice${aliceCounter++}`).buffer).then(function (ciphertext) {
            if (ciphertext.body) {
                
                console.log(chalk.red(ciphertext.body));
                console.log(chalk.green(`Bob Decrypts`));
                // check for ciphertext.type to be 3 which includes the PREKEY_BUNDLE
                return bobSessionCipher.decryptPreKeyWhisperMessage(ciphertext.body, 'binary');
            }
            return null;

        }).then(function (plaintext) {
            const msg =  new TextDecoder().decode(new Uint8Array(plaintext as ArrayBuffer));
            console.log(chalk.green(msg));
            const toSend = `messageToAliceFromBob${bobCounter++}`
            console.log(chalk.red(`Bob Encrypts: ${toSend}`));
            bobSessionCipher.encrypt(DataUtils.stringToArrayBuffer(`messageToAliceFromBob${bobCounter++}`)).then(function (ciphertext) {
                if (ciphertext.body) {
                    console.log(chalk.red(ciphertext.body));
                    console.log(chalk.green(`Alice Decrypts`));
                    return aliceSessionCipher.decryptWhisperMessage(ciphertext.body, 'binary');
                }
                return null;

            }).then(function (plaintext) {
                const msg =  new TextDecoder().decode(new Uint8Array(plaintext as ArrayBuffer));
                console.log(chalk.green(msg));
            });
        });

        setInterval(async () => {
            //console.log(await aliceSessionCipher.storage.loadSession(`${BOB_ADDRESS.getName()}.${BOB_ADDRESS.getDeviceId()}`));
            //console.log(await bobSessionCipher.storage.loadSession(`${ALICE_ADDRESS.getName()}.${ALICE_ADDRESS.getDeviceId()}`));

            const toSend = `messageToBobFromAlice${aliceCounter++}`;
            console.log(chalk.red(`Alice Encrypts: ${toSend}`));
            aliceSessionCipher.encrypt(DataUtils.stringToArrayBuffer(toSend)).then(function (ciphertext) {
                if (ciphertext.body) {
                    console.log(chalk.red(ciphertext.body));
                    // check for ciphertext.type to be 3 which includes the PREKEY_BUNDLE
                    console.log(chalk.green(`Bob Decrypts`));
                    return bobSessionCipher.decryptWhisperMessage(ciphertext.body, 'binary');
                }
                return null;

            }).then(function (plaintext) {
                const msg =  new TextDecoder().decode(new Uint8Array(plaintext as ArrayBuffer));
                console.log(chalk.green(msg));
                const toSend = `messageToAliceFromBob${bobCounter++}`
                console.log(chalk.red(`Bob Encrypts: ${toSend}`));
                bobSessionCipher.encrypt(DataUtils.stringToArrayBuffer(toSend)).then(function (ciphertext) {
                    if (ciphertext.body) {     
                        console.log(chalk.red(ciphertext.body));
                        console.log(chalk.green(`Alice Decrypts`));
                        return aliceSessionCipher.decryptWhisperMessage(ciphertext.body, 'binary');
                    }
                    return null;

                }).then(function (plaintext) {
                    const base64Str = DataUtils.arrayBufferToBase64String(plaintext as ArrayBuffer);
                    console.log(chalk.green(DataUtils.decodeBase64(base64Str)));
                });
            });

        }, 2000);
    });
});