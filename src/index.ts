import * as libsignal from '@privacyresearch/libsignal-protocol-typescript'
import { DeviceType, KeyPairType } from '@privacyresearch/libsignal-protocol-typescript';
import { DataUtils, SignalProtocolStore, } from './store/store';
import chalk from 'chalk';
import { Crypto } from "@peculiar/webcrypto";

const crypto = new Crypto();

const KeyHelper = libsignal.KeyHelper;

const TAG_LENGTH = 128;
const KEY_ALGO = {
    'name': 'AES-GCM',
    'length': 128
};

interface OmemoMessage {
    key_Base64: string
    tag_Base64: string,
    key_and_tag_Base64: string,
    payload_Base64: string,
    iv_Base64: string
}

async function encryptMessage (plaintext: string): Promise<OmemoMessage> {
    // The client MUST use fresh, randomly generated key/IV pairs
    // with AES-128 in Galois/Counter Mode (GCM).

    // For GCM a 12 byte IV is strongly suggested as other IV lengths
    // will require additional calculations. In principle any IV size
    // can be used as long as the IV doesn't ever repeat. NIST however
    // suggests that only an IV size of 12 bytes needs to be supported
    // by implementations.
    //
    // https://crypto.stackexchange.com/questions/26783/ciphertext-and-tag-size-and-iv-transmission-with-aes-in-gcm-mode
    const iv = crypto.getRandomValues(new Uint8Array(12)),
        key = await crypto.subtle.generateKey(KEY_ALGO, true, ['encrypt', 'decrypt']),
        algo = {
            'name': 'AES-GCM',
            'iv': iv,
            'tagLength': TAG_LENGTH
        },
        encrypted = await crypto.subtle.encrypt(algo, key, DataUtils.stringToArrayBuffer(plaintext)),
        length = encrypted.byteLength - ((128 + 7) >> 3),
        ciphertext = encrypted.slice(0, length),
        tag = encrypted.slice(length),
        exported_key = await crypto.subtle.exportKey('raw', key);

    return {
        key_Base64: DataUtils.arrayBufferToBase64String(exported_key),
        tag_Base64: DataUtils.arrayBufferToBase64String(tag),
        key_and_tag_Base64: DataUtils.arrayBufferToBase64String(DataUtils.appendArrayBuffer(exported_key, tag)),
        payload_Base64: DataUtils.arrayBufferToBase64String(ciphertext),
        iv_Base64: DataUtils.arrayBufferToBase64String(iv)
    };
}

async function decryptMessage (obj: OmemoMessage): Promise<string> {
    const key_obj = await crypto.subtle.importKey('raw', DataUtils.base64StringToArrayBuffer(obj.key_Base64), KEY_ALGO, true, ['encrypt', 'decrypt']);
    const cipher = DataUtils.appendArrayBuffer(DataUtils.base64StringToArrayBuffer(obj.payload_Base64), DataUtils.base64StringToArrayBuffer(obj.tag_Base64));
    const algo = {
        'name': 'AES-GCM',
        'iv': DataUtils.base64StringToArrayBuffer(obj.iv_Base64),
        'tagLength': TAG_LENGTH
    };
    return DataUtils.arrayBufferToString(await crypto.subtle.decrypt(algo, key_obj, cipher));
}

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

//TODO study the encryption and decryption that converse.js does
// https://github.com/conversejs/converse.js/blob/a4b90e3ab214647c44d048f9a54ee609e40206b5/src/plugins/omemo/utils.js#L17

//Does it relate to the current spec? https://xmpp.org/extensions/xep-0384.html

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
    process.then(async () => {
        var aliceSessionCipher = new libsignal.SessionCipher(aliceStore, BOB_ADDRESS);
        var bobSessionCipher = new libsignal.SessionCipher(bobStore, ALICE_ADDRESS);

        const toSend = JSON.stringify(await encryptMessage(`messageToBobFromAlice${aliceCounter++}`));
        //const toSend = await encryptMessage(`messageToBobFromAlice${aliceCounter++}`);
        console.log(chalk.red(`Alice Encrypts: ${toSend}`));
        aliceSessionCipher.encrypt(new TextEncoder().encode(toSend).buffer).then(async function (ciphertext) {
            if (ciphertext.body) {
                console.log(chalk.red(ciphertext.body));
                console.log(chalk.red(`Bob receives: ${ciphertext.body}`));
                console.log(chalk.green(`Bob Decrypts`));
                // check for ciphertext.type to be 3 which includes the PREKEY_BUNDLE
                const msg = DataUtils.arrayBufferToString(await bobSessionCipher.decryptPreKeyWhisperMessage(ciphertext.body, 'binary'));
                console.log(chalk.red(`Bob decrypts inner msg: ${msg}`));
                return await decryptMessage(JSON.parse(msg) as OmemoMessage);
            }
            return null;

        }).then(async function (plaintext) {
            console.log(chalk.green(plaintext));
            const toSend = JSON.stringify(await encryptMessage(`messageToAliceFromBob${bobCounter++}`));
            console.log(chalk.red(`Bob Encrypts: ${toSend}`));
            bobSessionCipher.encrypt(new TextEncoder().encode(toSend).buffer).then(async function (ciphertext) {
                if (ciphertext.body) {
                    console.log(chalk.red(ciphertext.body));
                    console.log(chalk.green(`Alice Decrypts`));
                    const msg = DataUtils.arrayBufferToString(await aliceSessionCipher.decryptWhisperMessage(ciphertext.body, 'binary'));
                    return await decryptMessage(JSON.parse(msg) as OmemoMessage);
                }
                return null;

            }).then(function (plaintext) {
                console.log(chalk.green(plaintext));
            });
        });

        setInterval(async () => {
            //console.log(await aliceSessionCipher.storage.loadSession(`${BOB_ADDRESS.getName()}.${BOB_ADDRESS.getDeviceId()}`));
            //console.log(await bobSessionCipher.storage.loadSession(`${ALICE_ADDRESS.getName()}.${ALICE_ADDRESS.getDeviceId()}`));
            const toSend = JSON.stringify(await encryptMessage(`messageToBobFromAlice${aliceCounter++}`));
            console.log(chalk.red(`Alice Encrypts: ${toSend}`));
            aliceSessionCipher.encrypt(DataUtils.stringToArrayBuffer(toSend)).then(async function (ciphertext) {
                if (ciphertext.body) {
                    console.log(chalk.red(ciphertext.body));
                    // check for ciphertext.type to be 3 which includes the PREKEY_BUNDLE
                    const msg = DataUtils.arrayBufferToString(await bobSessionCipher.decryptWhisperMessage(ciphertext.body, 'binary'));
                    console.log(chalk.red(`Bob decrypts inner msg: ${msg}`));
                    return await decryptMessage(JSON.parse(msg) as OmemoMessage);
                }
                return null;

            }).then(async function (plaintext) {
                console.log(chalk.green(plaintext));
                const toSend = JSON.stringify(await encryptMessage(`messageToAliceFromBob${bobCounter++}`));
                console.log(chalk.red(`Bob Encrypts: ${toSend}`));
                bobSessionCipher.encrypt(DataUtils.stringToArrayBuffer(toSend)).then(async function (ciphertext) {
                    if (ciphertext.body) {     
                        console.log(chalk.red(ciphertext.body));
                        console.log(chalk.green(`Alice Decrypts`));
                        const msg = DataUtils.arrayBufferToString(await aliceSessionCipher.decryptWhisperMessage(ciphertext.body, 'binary'));
                        return await decryptMessage(JSON.parse(msg) as OmemoMessage);
                    }
                    return null;

                }).then(function (plaintext) {
                    //const base64Str = DataUtils.arrayBufferToBase64String(plaintext as ArrayBuffer);
                    //console.log(chalk.green(DataUtils.decodeBase64(base64Str)));
                    console.log(chalk.green(plaintext));
                });
            });

        }, 2000);
    });
});