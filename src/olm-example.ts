import { Account, init as olmInit, Session, Utility } from 'olm';
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

interface Bundle {
    ik: string;
    spks: string;
    spkId: number;
    spk: string;
    prekeys: Array<{
        id: number;
        key: any;
    }>;
}

async function initialiseSession(sjid: string, session: Session, account: Account, store: LocalStorageStore, bundle: Bundle, rjid: string): Promise<EncryptedMessage | null> {
    const pickledAccountId = store.get('pickledAccountId');
    const pickledSessionId = store.get('pickledSessionId');

    const pickledSession = store.get('session');
    const pickledAccount = store.get('account');

    if (pickledSession && pickledAccount) {
        console.log(chalk.blue(`Load ${sjid}'s session: ${pickledSession}`));
        session.unpickle(pickledSessionId as string, pickledSession);
        console.log(chalk.blue(`${sjid}'s loaded session id: ${session.session_id()}`));
        account.unpickle(pickledAccountId as string, pickledAccount);
        return null;
    } else {
        // Establish initial sesssion
        account.create();

        const idKey = JSON.parse(account.identity_keys()).curve25519;
        store.set('id', idKey);

        try {
            const u = new Utility();
            u.ed25519_verify(bundle.spk, bundle.spkId + bundle.ik, bundle.spks);
            u.free();
        } catch (e) {
            // handle an untrusted bundle
            throw e;
        }

        console.log(chalk.blue(`${sjid}'s verified ${rjid}'s identity`));
        // TODO implement isTrusted
        store.set(`identity/${rjid}`, bundle.ik);

        const otk_id = bundle.prekeys[0]; //Grab a random key

        console.log(chalk.blue(`${sjid} gets ${rjid}'s prekey: ${otk_id.key}`));

        session.create_outbound(
            account, bundle.ik, otk_id.key
        );

            
        store.set('account', account.pickle(pickledAccountId as string));
        

        return encryptMessage('', session, rjid, store); //prepareMessage('', session, store, rjid);
    }
}

async function processMessage(sjid: string, session: Session, account: Account, store: LocalStorageStore, message: EncryptedMessage): Promise<string> {
    if (!session.has_received_message() && message.type === 0) {
        // if we have never received messages by this point something has gone wrong
        // TODO handle this case before decryptiong? How? Ask sender for a new session key exchange? What is the protocol? See below.
        session.create_inbound(account, message.key_base64);
        const pickledAccountId = crypto.getRandomValues(new Uint32Array(1))[0].toString();
        store.set('pickledAccountId', pickledAccountId);
        store.set('account', account.pickle(pickledAccountId));

        const plaintext = await decryptMessage(sjid, message, session, store);

        account.remove_one_time_keys(session);
        return plaintext;
        // console.log(session.matches_inbound((message as any).body));
        //await session.decrypt((message as any).type, (message as any).body);
        
        // console.log(session.matches_inbound((message as any).body));
    } else {
        // console.log(chalk.rgb(255, 191, 0)(`Bob receives: ${JSON.stringify(message)}`));

        // TODO handle OLM.BAD_MESSAGE_MAC error through try and catch
        // TODO from the XEP:
        // There are various reasons why decryption of an
        // OMEMOKeyExchange or an OMEMOAuthenticatedMessage
        // could fail. One reason is if the message was
        // received twice and already decrypted once, in this
        // case the client MUST ignore the decryption failure
        // and not show any warnings/errors. In all other cases
        // of decryption failure, clients SHOULD respond by
        // forcibly doing a new key exchange and sending a new
        // OMEMOKeyExchange with a potentially empty SCE
        // payload. By building a new session with the original
        // sender this way, the invalid session of the original
        // sender will get overwritten with this newly created,
        // valid session.
        return await decryptMessage(sjid, message, session, store);
    }
}

async function decryptMessage(sjid:string, encryptedMessage: EncryptedMessage, session: Session, store: LocalStorageStore): Promise<string> {

    const decryptedKey = session.decrypt(encryptedMessage.type, encryptedMessage.key_base64);

    const pickledSessionId = store.get('pickledSessionId'); // this is null on initialise
    store.set(`identity/${sjid}`, encryptedMessage.sid);
    const pickledSession = session.pickle(pickledSessionId as string);
    store.set('session', pickledSession);

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

async function encryptMessage(plaintext: string, session: Session, rjid: string, store: LocalStorageStore): Promise<EncryptedMessage> {
    const rid = store.get(`identity/${rjid}`) as string;
    const sid = store.get('id') as string;
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

    const pickledSessionId = store.get('pickledAccountId');
    const pickledSession = session.pickle(pickledSessionId as string);
    store.set('session', pickledSession);

    return {
        rid,
        sid,
        iv_base64: DataUtils.arrayBufferToBase64String(iv),
        key_base64: (encryptedKey as any).body,
        payload_base64: DataUtils.arrayBufferToBase64String(ciphertext),
        type: (encryptedKey as any).type
    }
}

function getBundle(idKey: string, account: Account,): Bundle {
    const randomIds = crypto.getRandomValues(new Uint32Array(1));
    account.generate_one_time_keys(100);

    const oneTimePreKeys = JSON.parse(account.one_time_keys()).curve25519;
    const signedPreKeyId = randomIds[0];
    const signature = account.sign(signedPreKeyId + idKey);

    account.mark_keys_as_published();

    return {
        ik: idKey,
        spks: signature,
        spkId: signedPreKeyId,
        spk: JSON.parse(account.identity_keys()).ed25519,
        prekeys: Object.keys(oneTimePreKeys).map((x, i) => {
            return {
                id: i,
                key: oneTimePreKeys[x]
            }
        })
    }
}

(async () => {
    await olmInit();

    //Storage, session and account setup

    const aliceStore: LocalStorageStore = new LocalStorageStore('alice_store');
    const bobStore: LocalStorageStore = new LocalStorageStore('bob_store');

    let aliceCounter = 0;
    let bobCounter = 0;

    const aliceSession = new Session();
    const bobSession = new Session();
    const aliceAccount = new Account();
    const bobAccount = new Account();

    aliceAccount.create();
    bobAccount.create();

    const aliceIdKey = JSON.parse(aliceAccount.identity_keys()).curve25519;
    const bobIdKey = JSON.parse(bobAccount.identity_keys()).curve25519;
    aliceStore.set('id', aliceIdKey);
    bobStore.set('id', bobIdKey);

    const pickledAccountId = crypto.getRandomValues(new Uint32Array(2));
    const pickledSessionId = crypto.getRandomValues(new Uint32Array(2));

    aliceStore.set('pickledSessionId', pickledSessionId[0].toString());
    aliceStore.set('pickledAccountId', pickledAccountId[0].toString());

    bobStore.set('pickledSessionId', pickledSessionId[1].toString());
    bobStore.set('pickledAccountId', pickledAccountId[1].toString());
    
    //session init

    const bobsBundle = getBundle(bobIdKey, bobAccount);
    console.log(chalk.rgb(255, 191, 0)(`Alice gets Bob's bundle: ${JSON.stringify(bobsBundle)}`));

    const initialMessage = await initialiseSession('alice', aliceSession, aliceAccount, aliceStore, bobsBundle, 'bob');

    //bob receives key exchange
    await processMessage('alice', bobSession, bobAccount, bobStore, initialMessage as EncryptedMessage);

    setInterval(async () => {
        let toSend = `messageToBobFromAlice${aliceCounter++}`;

        console.log(chalk.red(`alice Encrypts: ${toSend}`));
        let encryptedMessage = await encryptMessage(toSend, aliceSession, 'bob', aliceStore);

        let plaintext = null;
        //bob receives first proper message after key exchange
        console.log(chalk.rgb(255, 191, 0)(`bob receives from alice: ${JSON.stringify(encryptedMessage)}`));
        plaintext = await processMessage('alice', bobSession, bobAccount, bobStore, encryptedMessage);

        console.log(chalk.green(`bob Decrypts: ${plaintext}`));
        toSend = `messageToAliceFromBob${bobCounter++}`;

        encryptedMessage = await encryptMessage(toSend, bobSession, 'alice', bobStore);
        console.log(chalk.red(`bob Encrypts: ${toSend}`));

        console.log(chalk.rgb(255, 191, 0)(`alice receives: ${JSON.stringify(encryptedMessage)}`));
        plaintext = await processMessage('bob', aliceSession, aliceAccount, aliceStore, encryptedMessage);
        console.log(chalk.green(`Alice Decrypts: ${plaintext}`));
        
    }, 2000);

})();