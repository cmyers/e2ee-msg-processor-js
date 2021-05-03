import * as libsignal from '@privacyresearch/libsignal-protocol-typescript'
import { DeviceType, KeyPairType, SessionCipher } from '@privacyresearch/libsignal-protocol-typescript';
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

interface EncryptedMessage {
    key_base64: string
    tag_base64: string,
    key_and_tag_base64: string,
    payload_base64: string,
    iv_base64: string
}

interface OmemoMessage {
    key_base64: string,
    iv_base64: string,
    payload_base64: string
}

async function encryptMessage(plaintext: string): Promise<EncryptedMessage> {
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
        key_base64: DataUtils.arrayBufferToBase64String(exported_key),
        tag_base64: DataUtils.arrayBufferToBase64String(tag),
        key_and_tag_base64: DataUtils.arrayBufferToBase64String(DataUtils.appendArrayBuffer(exported_key, tag)),
        payload_base64: DataUtils.arrayBufferToBase64String(ciphertext),
        iv_base64: DataUtils.arrayBufferToBase64String(iv)
    };
}

async function decryptMessage(obj: OmemoMessage): Promise<string> {
    const key = DataUtils.base64StringToArrayBuffer(obj.key_base64).slice(0, 16);
    const tag = DataUtils.base64StringToArrayBuffer(obj.key_base64).slice(16);

    const key_obj = await crypto.subtle.importKey('raw', key, KEY_ALGO, true, ['encrypt', 'decrypt']);
    const cipher = DataUtils.appendArrayBuffer(DataUtils.base64StringToArrayBuffer(obj.payload_base64), tag);
    const algo = {
        'name': 'AES-GCM',
        'iv': DataUtils.base64StringToArrayBuffer(obj.iv_base64),
        'tagLength': TAG_LENGTH
    };
    return DataUtils.arrayBufferToString(await crypto.subtle.decrypt(algo, key_obj, cipher));
}

(async () => {
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

    // TODO study the encryption and decryption that converse.js does
    // https://github.com/conversejs/converse.js/blob/a4b90e3ab214647c44d048f9a54ee609e40206b5/src/plugins/omemo/utils.js#L17

    // Does it relate to the current spec? https://xmpp.org/extensions/xep-0384.html

    var ALICE_ADDRESS = new libsignal.SignalProtocolAddress("alice@localhost", 1234);
    var BOB_ADDRESS = new libsignal.SignalProtocolAddress("bob@localhost", 5678);

    // TODO load sessions from file
    var aliceStore = new SignalProtocolStore("alice_localhost");
    var bobStore = new SignalProtocolStore("bob_localhost");

    var bobPreKeyId = KeyHelper.generateRegistrationId();
    var bobSignedKeyId = KeyHelper.generateRegistrationId();


    const hasSession = aliceStore.containsKey('alice_localhost/session');
    let aliceCounter = 0;
    let bobCounter = 0;
    var aliceSessionCipher: libsignal.SessionCipher;
    var bobSessionCipher: libsignal.SessionCipher;

    if (hasSession) {
        aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
        bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);
    } else {
        await generateIdentity(aliceStore);
        await generateIdentity(bobStore);
        const preKeyBundle = await generatePreKeyBundle(bobStore, bobPreKeyId, bobSignedKeyId);

        var builder = new libsignal.SessionBuilder(aliceStore, BOB_ADDRESS);
        await builder.processPreKey(preKeyBundle as DeviceType<ArrayBuffer>);
        aliceSessionCipher = new libsignal.SessionCipher(aliceStore, BOB_ADDRESS);
        bobSessionCipher = new libsignal.SessionCipher(bobStore, ALICE_ADDRESS);
    }

    setInterval(async () => {
        const toSend = `messageToBobFromAlice${aliceCounter++}`;
        const encryptedMessage = (await encryptMessage(toSend));

        console.log(chalk.red(`Alice Encrypts: ${toSend}`));
        let ciphertext = await aliceSessionCipher.encrypt(DataUtils.base64StringToArrayBuffer(encryptedMessage.key_and_tag_base64));
        let plaintext = null;

        if (ciphertext.body) {

            const omemoMessage: OmemoMessage = {
                iv_base64: encryptedMessage.iv_base64,
                key_base64: DataUtils.encodeBase64(ciphertext.body),
                payload_base64: encryptedMessage.payload_base64
            }

            console.log(chalk.red(`Bob receives: ${JSON.stringify(omemoMessage)}`));
            // check for ciphertext.type to be 3 which includes the PREKEY_BUNDLE
            let msg: ArrayBuffer;
            if (ciphertext.type === 3) {
                msg = await bobSessionCipher.decryptPreKeyWhisperMessage(DataUtils.base64StringToArrayBuffer(omemoMessage.key_base64), 'binary');
            } else {
                msg = await bobSessionCipher.decryptWhisperMessage(DataUtils.base64StringToArrayBuffer(omemoMessage.key_base64), 'binary');
            }

            omemoMessage.key_base64 = DataUtils.arrayBufferToBase64String(msg);
            console.log(chalk.red(`Bob decrypts inner msg: ${omemoMessage.key_base64}`));

            plaintext = await decryptMessage(omemoMessage);
        }

        if (plaintext !== null) {
            console.log(chalk.green(`Bob Decrypts: ${plaintext}`));

            const toSend = `messageToAliceFromBob${bobCounter++}`;
            const encryptedMessage = (await encryptMessage(toSend));
            console.log(chalk.red(`Bob Encrypts: ${toSend}`));

            ciphertext = await bobSessionCipher.encrypt(DataUtils.base64StringToArrayBuffer(encryptedMessage.key_and_tag_base64));
            plaintext = null;
            if (ciphertext.body) {

                const omemoMessage: OmemoMessage = {
                    iv_base64: encryptedMessage.iv_base64,
                    key_base64: DataUtils.encodeBase64(ciphertext.body),
                    payload_base64: encryptedMessage.payload_base64
                }

                console.log(chalk.red(`Alice receives: ${JSON.stringify(omemoMessage)}`));
                const msg = await aliceSessionCipher.decryptWhisperMessage(DataUtils.base64StringToArrayBuffer(omemoMessage.key_base64), 'binary');
                omemoMessage.key_base64 = DataUtils.arrayBufferToBase64String(msg);
                console.log(chalk.red(`Alice decrypts inner msg: ${omemoMessage.key_base64}`));

                plaintext = await decryptMessage(omemoMessage);
            }

            if (plaintext !== null) {
                console.log(chalk.green(`Alice Decrypts: ${plaintext}`));
            }
        }
    }, 2000);
})();