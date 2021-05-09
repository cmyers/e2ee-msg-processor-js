import { Account, init as olmInit, Session } from 'olm';
import { Crypto } from "@peculiar/webcrypto";
import { DataUtils } from './store/store';
import chalk from 'chalk';

// TODO Read this about signing prekeys https://gitlab.matrix.org/matrix-org/olm/-/blob/master/docs/signing.md

const crypto = new Crypto();

const TAG_LENGTH = 128;

const KEY_ALGO = {
    'name': 'AES-GCM',
    'length': 128
};

interface EncryptedMessage {
    iv_base64: string,
    key_base64: string,
    payload_base64: string,
    type: number
}

async function decryptMessage(encryptedMessage: EncryptedMessage, session:Session): Promise<string> {

    const decryptedKey = session.decrypt(encryptedMessage.type, encryptedMessage.key_base64);

    const key = DataUtils.base64StringToArrayBuffer(decryptedKey).slice(0, 16);
    const tag = DataUtils.base64StringToArrayBuffer(decryptedKey).slice(16);

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

async function encryptMessage(plaintext: string, session: Session): Promise<EncryptedMessage> {
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
        exported_key = await crypto.subtle.exportKey('raw', key),
        key_tag = DataUtils.arrayBufferToBase64String(DataUtils.appendArrayBuffer(exported_key, tag));

        const encryptedKey = session.encrypt(key_tag);

    return {
        iv_base64: DataUtils.arrayBufferToBase64String(iv),
        key_base64: (encryptedKey as any).body,
        payload_base64: DataUtils.arrayBufferToBase64String(ciphertext),
        type: (encryptedKey as any).type
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

    // Establish initial sesssion

    bobAccount.generate_one_time_keys(1);
    const bobOneTimeKeys = JSON.parse(bobAccount.one_time_keys()).curve25519;
    bobAccount.mark_keys_as_published();

    const bobIdKey = JSON.parse(bobAccount.identity_keys()).curve25519;
    console.log(chalk.blue(`Alice gets Bob's Id key: ${bobIdKey}`));

    const otk_id = Object.keys(bobOneTimeKeys)[0];

    console.log(chalk.blue(`Alice gets Bob's prekey: ${bobOneTimeKeys[otk_id]}`));

    aliceSession.create_outbound(
        aliceAccount, bobIdKey, bobOneTimeKeys[otk_id]
    );

    const initialMessage = aliceSession.encrypt('');

    bobSession.create_inbound(bobAccount, (initialMessage as any).body);
    bobAccount.remove_one_time_keys(bobSession);
    bobSession.decrypt((initialMessage as any).type, (initialMessage as any).body);
    
    setInterval(async () => {
        const toSend = `messageToBobFromAlice${aliceCounter++}`;
        console.log(chalk.red(`Alice Encrypts: ${toSend}`));

        const encryptedMessage = await encryptMessage(toSend, aliceSession);

        //const pickled = aliceSession.pickle('test');
        //aliceSession.unpickle('test', pickled);
        
        let plaintext = null;

        console.log(chalk.rgb(255, 191, 0)(`Bob receives: ${JSON.stringify(encryptedMessage)}`));
        plaintext = await decryptMessage(encryptedMessage, bobSession);

        if (plaintext !== null) {
            console.log(chalk.green(`Bob Decrypts: ${plaintext}`));

            const toSend = `messageToAliceFromBob${bobCounter++}`;

            const encryptedMessage = await encryptMessage(toSend, bobSession);

            console.log(chalk.red(`Bob Encrypts: ${toSend}`));

            console.log(chalk.rgb(255, 191, 0)(`Alice receives: ${JSON.stringify(encryptedMessage)}`));
            plaintext = await decryptMessage(encryptedMessage, aliceSession);

            if (plaintext !== null) {
                console.log(chalk.green(`Alice Decrypts: ${plaintext}`));
            }
        }
    }, 2000);



})();