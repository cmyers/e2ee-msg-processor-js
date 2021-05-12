import { Account, init as olmInit, Session } from 'olm';
import { Crypto } from "@peculiar/webcrypto";
import { DataUtils, LocalStorageStore } from './store/store';
import chalk from 'chalk';

// TODO Read this about signing prekeys https://gitlab.matrix.org/matrix-org/olm/-/blob/master/docs/signing.md

const crypto = new Crypto();

const TAG_LENGTH = 128;

const KEY_ALGO = {
    'name': 'AES-GCM',
    'length': 128
};

interface EncryptedMessage {
    rid: string,
    sid: string,
    iv_base64: string,
    key_base64: string,
    payload_base64: string,
    type: number
}

async function decryptMessage(encryptedMessage: EncryptedMessage, session: Session): Promise<string> {

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

async function encryptMessage(plaintext: string, session: Session, rid: string, sid: string): Promise<EncryptedMessage> {
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
        rid,
        sid,
        iv_base64: DataUtils.arrayBufferToBase64String(iv),
        key_base64: (encryptedKey as any).body,
        payload_base64: DataUtils.arrayBufferToBase64String(ciphertext),
        type: (encryptedKey as any).type
    }
}

(async () => {
    await olmInit();

    const aliceStore: LocalStorageStore = new LocalStorageStore('alice_store');
    const bobStore: LocalStorageStore = new LocalStorageStore('bob_store');

    let aliceCounter = 0;
    let bobCounter = 0;

    const aliceSession = new Session();
    const bobSession = new Session();
    const aliceAccount = new Account();
    const bobAccount = new Account();

    const alicePickledSession = aliceStore.get('session');
    const alicePickledAccount = aliceStore.get('account');

    if (alicePickledSession && alicePickledAccount) {
        console.log(chalk.blue(`Load Alice's session: ${alicePickledSession}`));
        aliceSession.unpickle(aliceStore.get('bobIdKey') as string, alicePickledSession);
        console.log(chalk.blue(`Alice's loaded session id: ${aliceSession.session_id()}`));
        aliceAccount.unpickle('account', alicePickledAccount);
    } else {
        // Establish initial sesssion
        aliceAccount.create();
        bobAccount.create();

        bobAccount.generate_one_time_keys(100);
        const bobOneTimeKeys = JSON.parse(bobAccount.one_time_keys()).curve25519;
        bobAccount.mark_keys_as_published();

        const aliceIdKey = JSON.parse(aliceAccount.identity_keys()).curve25519;
        const bobIdKey = JSON.parse(bobAccount.identity_keys()).curve25519;
        aliceStore.set('id', aliceIdKey);
        bobStore.set('id', bobIdKey);
        aliceStore.set('bobIdKey', bobIdKey);

        console.log(chalk.blue(`Alice gets Bob's Id key: ${bobIdKey}`));

        const randomIds = crypto.getRandomValues(new Uint32Array(1));
        const signedPreKeyId = randomIds[0];

        const prekey = await crypto.subtle.generateKey({ name: "EdDSA", namedCurve: "Ed25519" }, true, ["sign", "verify"]);

        const preKeySign = await crypto.subtle.sign({ name: "EdDSA" }, prekey.privateKey, DataUtils.stringToArrayBuffer(bobIdKey));

        const exportedKey = await crypto.subtle.exportKey('jwk', prekey.publicKey);

        const bundle = {
            ik: bobIdKey,
            spks: preKeySign,
            spkId: signedPreKeyId,
            spk: DataUtils.encodeBase64(JSON.stringify(exportedKey)),
            prekeys: Object.keys(bobOneTimeKeys)
        }

        const key_obj = await crypto.subtle.importKey('jwk', JSON.parse(DataUtils.decodeBase64(bundle.spk)) as JsonWebKey, { name: "EdDSA", namedCurve: "Ed25519" }, true, ["sign", "verify"]);

        const verify = await crypto.subtle.verify({ name: "EdDSA" }, key_obj, bundle.spks, DataUtils.stringToArrayBuffer(bundle.ik));

        console.log(chalk.blue(`Alice verifies Bob's identity: ${verify}`));

        const otk_id = bundle.prekeys[0];

        console.log(chalk.blue(`Alice gets Bob's prekey: ${bobOneTimeKeys[otk_id]}`));

        aliceSession.create_outbound(
            aliceAccount, bobIdKey, bobOneTimeKeys[otk_id]
        );

        aliceStore.set('account', aliceAccount.pickle('account'));

        const initialMessage = aliceSession.encrypt('');

        bobSession.create_inbound(bobAccount, (initialMessage as any).body);
        bobStore.set('account', bobAccount.pickle('account'));

        bobAccount.remove_one_time_keys(bobSession);
        bobSession.decrypt((initialMessage as any).type, (initialMessage as any).body);
    }

    setInterval(async () => {
        const toSend = `messageToBobFromAlice${aliceCounter++}`;

        console.log(chalk.red(`Alice Encrypts: ${toSend}`));
        const encryptedMessage = await encryptMessage(toSend, aliceSession, aliceStore.get('bobIdKey') as string, aliceStore.get('id') as string);

        const pickled = aliceSession.pickle(aliceStore.get('bobIdKey') as string);
        aliceStore.set('session', pickled);

        let plaintext = null;

        const bobPickledSession = bobStore.get('session');
        const bobPickledAccount = bobStore.get('account');

        if (bobPickledSession && !bobSession.has_received_message() && bobPickledAccount) {
            console.log(chalk.blue(`Load Bob's session: ${bobPickledSession}`));
            bobSession.unpickle(bobStore.get('aliceIdKey') as string, bobPickledSession);
            console.log(chalk.blue(`Bob's loaded session id: ${bobSession.session_id()}`));
            bobAccount.unpickle('account', bobPickledAccount);
        }

        console.log(chalk.rgb(255, 191, 0)(`Bob receives: ${JSON.stringify(encryptedMessage)}`));
        plaintext = await decryptMessage(encryptedMessage, bobSession);

        bobStore.set('aliceIdKey', encryptedMessage.sid);
        const bobPickled = bobSession.pickle(bobStore.get('aliceIdKey') as string);
        bobStore.set('session', bobPickled);

        if (plaintext !== null) {
            console.log(chalk.green(`Bob Decrypts: ${plaintext}`));
            const toSend = `messageToAliceFromBob${bobCounter++}`;

            const bobEncryptedMessage = await encryptMessage(toSend, bobSession, bobStore.get('aliceIdKey') as string, bobStore.get('id') as string);
            console.log(chalk.red(`Bob Encrypts: ${toSend}`));

            const pickled = bobSession.pickle(bobStore.get('aliceIdKey') as string);
            bobStore.set('session', pickled);

            console.log(chalk.rgb(255, 191, 0)(`Alice receives: ${JSON.stringify(bobEncryptedMessage)}`));
            plaintext = await decryptMessage(bobEncryptedMessage, aliceSession);
            const alicePickled = aliceSession.pickle(aliceStore.get('bobIdKey') as string);
            aliceStore.set('session', alicePickled);

            if (plaintext !== null) {
                console.log(chalk.green(`Alice Decrypts: ${plaintext}`));
            }
        }
    }, 2000);

})();