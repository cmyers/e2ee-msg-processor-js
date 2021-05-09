import { Account, init as olmInit, Session } from 'olm';
import { Crypto } from "@peculiar/webcrypto";
import { DataUtils } from './store/store';
import chalk from 'chalk';

const crypto = new Crypto();

const TAG_LENGTH = 128;

const KEY_ALGO = {
    'name': 'AES-GCM',
    'length': 128
};

interface EncryptedMessage {
    iv_base64: string,
    key_base64: string,
    payload_base64: string
}

async function decryptMessage(encryptedMessage: EncryptedMessage): Promise<string> {
    const key = DataUtils.base64StringToArrayBuffer(encryptedMessage.key_base64).slice(0, 16);
    const tag = DataUtils.base64StringToArrayBuffer(encryptedMessage.key_base64).slice(16);

    const key_obj = await crypto.subtle.importKey('raw', key, KEY_ALGO, true, ['encrypt', 'decrypt']);

    const cipher = DataUtils.appendArrayBuffer(DataUtils.base64StringToArrayBuffer(encryptedMessage.payload_base64), tag);

    const algo = {
        'name': 'AES-GCM',
        'iv': DataUtils.base64StringToArrayBuffer(encryptedMessage.iv_base64),
        'tagLength': TAG_LENGTH
    };

    const decryptedArrayBuffer = await crypto.subtle.decrypt(algo, key_obj, cipher);

    return DataUtils.arrayBufferToString(decryptedArrayBuffer);
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
        iv_base64: DataUtils.arrayBufferToBase64String(iv),
        key_base64: DataUtils.arrayBufferToBase64String(DataUtils.appendArrayBuffer(exported_key, tag)),
        payload_base64: DataUtils.arrayBufferToBase64String(ciphertext)
    }
}

(async () => {
    await olmInit();

    const aliceAccount = new Account();
    const bobAccount = new Account();
    aliceAccount.create();
    bobAccount.create();

    let aliceCounter = 0;
    let bobCounter = 0;

    const aliceSession = new Session();
    const bobSession = new Session();

    setInterval(async () => {
        const toSend = `messageToBobFromAlice${aliceCounter++}`;
        const encryptedMessage = await encryptMessage(toSend);

        bobAccount.generate_one_time_keys(1);
        const bobOneTimeKeys = JSON.parse(bobAccount.one_time_keys()).curve25519;
        bobAccount.mark_keys_as_published();

        const bobIdKey = JSON.parse(bobAccount.identity_keys()).curve25519;

        const otk_id = Object.keys(bobOneTimeKeys)[0];

        aliceSession.create_outbound(
            aliceAccount, bobIdKey, bobOneTimeKeys[otk_id]
        );

        //const pickled = aliceSession.pickle('test');
        //aliceSession.unpickle('test', pickled);

        const encrypted = aliceSession.encrypt(encryptedMessage.key_base64);
        encryptedMessage.key_base64 = (encrypted as any).body;

        console.log(chalk.red(`Alice Encrypts: ${toSend}`));
        let plaintext = null;

        console.log(chalk.rgb(255, 191, 0)(`Bob receives: ${JSON.stringify(encryptedMessage)}`));

        bobSession.create_inbound(bobAccount, (encrypted as any).body);
        bobAccount.remove_one_time_keys(bobSession);

        const decrypted = bobSession.decrypt((encrypted as any).type, encryptedMessage.key_base64);
        encryptedMessage.key_base64 = decrypted;

        plaintext = await decryptMessage(encryptedMessage);

        if (plaintext !== null) {
            console.log(chalk.green(`Bob Decrypts: ${plaintext}`));

            const toSend = `messageToAliceFromBob${bobCounter++}`;
            const encryptedMessage = await encryptMessage(toSend);

            aliceAccount.generate_one_time_keys(1);
            const aliceOneTimeKeys = JSON.parse(aliceAccount.one_time_keys()).curve25519;
            aliceAccount.mark_keys_as_published();

            const aliceIdKey = JSON.parse(aliceAccount.identity_keys()).curve25519;

            const otk_id = Object.keys(aliceOneTimeKeys)[0];

            bobSession.create_outbound(
                bobAccount, aliceIdKey, aliceOneTimeKeys[otk_id]
            );

            const encrypted = bobSession.encrypt(encryptedMessage.key_base64);
            encryptedMessage.key_base64 = (encrypted as any).body;

            console.log(chalk.red(`Bob Encrypts: ${toSend}`));

            console.log(chalk.rgb(255, 191, 0)(`Alice receives: ${JSON.stringify(encryptedMessage)}`));

            aliceSession.create_inbound(aliceAccount, (encrypted as any).body);
            aliceAccount.remove_one_time_keys(aliceSession);

            const decrypted = aliceSession.decrypt((encrypted as any).type, encryptedMessage.key_base64);
            encryptedMessage.key_base64 = decrypted;

            plaintext = await decryptMessage(encryptedMessage);


            if (plaintext !== null) {
                console.log(chalk.green(`Alice Decrypts: ${plaintext}`));
            }
        }
    }, 2000);



})();