import { Account, init as olmInit, Session, Utility } from 'olm';
import { Crypto } from "@peculiar/webcrypto";
import { DataUtils, LocalStorageStore } from './store/store';
import chalk from 'chalk';

// TODO handle corrupt sessions - request new session logic if can't decrypt, informing sender to initialise a new session and resend message

const crypto = new Crypto();

const TAG_LENGTH = 128;

//storage constants
const PICKLED_ACCOUNT_ID = 'pickledAccountId';
const PICKLED_SESSION_ID = 'pickledSessionId';
const PICKLED_SESSION = 'pickledSession';
const PICKLED_ACCOUNT = 'pickledAccount';
const IDENTITY_PREFIX = 'identity/';
const IDENTITY_KEY = 'identityKey';

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

async function encryptMessage(plaintext: string, session: Session, rjid: string, store: LocalStorageStore): Promise<EncryptedMessage> {
    const rid = store.get(`${IDENTITY_PREFIX}${rjid}`) as string;
    const sid = store.get(IDENTITY_KEY) as string;
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

    const pickledSessionId = store.get(PICKLED_SESSION_ID);
    const pickledSession = session.pickle(pickledSessionId as string);
    store.set(PICKLED_SESSION, pickledSession);

    return {
        rid,
        sid,
        iv_base64: DataUtils.arrayBufferToBase64String(iv),
        key_base64: (encryptedKey as any).body,
        payload_base64: DataUtils.arrayBufferToBase64String(ciphertext),
        type: (encryptedKey as any).type
    }
}

async function processMessage(sjid: string, session: Session, account: Account, store: LocalStorageStore, message: EncryptedMessage): Promise<string> {
    if (!session.has_received_message() && message.type === 0) {
        // if we have never received messages by this point something has gone wrong
        // TODO handle this case before decryptiong? How? Ask sender for a new session key exchange? What is the protocol? See below.
        session.create_inbound(account, message.key_base64);

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



async function decryptMessage(sjid: string, encryptedMessage: EncryptedMessage, session: Session, store: LocalStorageStore): Promise<string> {

    const decryptedKey = session.decrypt(encryptedMessage.type, encryptedMessage.key_base64);

    const pickledSessionId = store.get(PICKLED_SESSION_ID); // this is null on initialise
    store.set(`${IDENTITY_PREFIX}${sjid}`, encryptedMessage.sid);
    const pickledSession = session.pickle(pickledSessionId as string);
    store.set(PICKLED_SESSION, pickledSession);

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

class SessionManager {
    private _session!: Session;
    private _account!: Account;
    private _store: LocalStorageStore;
    private _idKey: string | null = null;
    private _jid: string;
    private _pickledAccountId: string | null = null;
    private _pickledSessionId: string | null = null;
    private _initialised: boolean = false;

    constructor(jid: string) {
        this._jid = jid;
        this._store = new LocalStorageStore(jid);
    }

    public async initialise() {
        await olmInit();
        this._session = new Session();
        this._account = new Account();

        this._pickledAccountId = this._store.get(PICKLED_ACCOUNT_ID);
        this._pickledSessionId = this._store.get(PICKLED_SESSION_ID);

        const pickledSession = this._store.get(PICKLED_SESSION);
        const pickledAccount = this._store.get(PICKLED_ACCOUNT);

        if (pickledSession && pickledAccount) {
            console.log(chalk.blue(`Load ${this._jid}'s session: ${pickledSession}`));
            this._session.unpickle(this._pickledSessionId as string, pickledSession);
            console.log(chalk.blue(`${this._jid}'s loaded session id: ${this._session.session_id()}`));
            this._account.unpickle(this._pickledAccountId as string, pickledAccount);
        } else {
            this._account.create();

            const randValues = crypto.getRandomValues(new Uint32Array(2));

            this._pickledAccountId = randValues[0].toString();
            this._store.set(PICKLED_ACCOUNT_ID, this._pickledAccountId);
            this._store.set(PICKLED_ACCOUNT, this._account.pickle(this._pickledAccountId));

            this._pickledSessionId = randValues[1].toString();
            this._store.set(PICKLED_SESSION_ID, this._pickledSessionId);
            this._store.set(PICKLED_ACCOUNT, this._account.pickle(this._pickledAccountId));
        }

        this._idKey = JSON.parse(this._account.identity_keys()).curve25519;
        this._store.set(IDENTITY_KEY, this._idKey);
    }

    get Session(): Session {
        return this._session;
    }

    get Account(): Account {
        return this._account;
    }

    get Store(): LocalStorageStore {
        return this._store;
    }

    get IdentityKey(): string {
        return this._idKey as string;
    }

    get Initialised(): boolean {
        return this._initialised;
    }

    public HasSessionWith(jid: string): boolean {
        return this._store.get(`${IDENTITY_PREFIX}${jid}`) ? true : false;
    }

    async initialiseSession(bundle: Bundle, rjid: string): Promise<EncryptedMessage | null> {
        try {
            const u = new Utility();
            u.ed25519_verify(bundle.spk, bundle.spkId + bundle.ik, bundle.spks);
            u.free();
        } catch (e) {
            // handle an untrusted bundle
            throw e;
        }

        console.log(chalk.blue(`${this._jid}'s verified ${rjid}'s identity`));
        // TODO implement isTrusted
        this._store.set(`${IDENTITY_PREFIX}${rjid}`, bundle.ik);

        const otk_id = bundle.prekeys[0]; //Grab a random key

        console.log(chalk.blue(`${this._jid} gets ${rjid}'s prekey: ${otk_id.key}`));

        this._session.create_outbound(
            this._account, bundle.ik, otk_id.key
        );

        this._store.set(PICKLED_ACCOUNT, this._account.pickle(this._pickledAccountId as string));

        return encryptMessage('', this._session, rjid, this._store);
    }
}

(async () => {
    const alice = new SessionManager('alice');
    await alice.initialise();
    const bob = new SessionManager('bob');
    await bob.initialise();

    let aliceCounter = 0;
    let bobCounter = 0;
    //session init

    const bobsBundle = getBundle(bob.IdentityKey, bob.Account);
    console.log(chalk.rgb(255, 191, 0)(`Alice gets Bob's bundle: ${JSON.stringify(bobsBundle)}`));


    if(!alice.HasSessionWith('bob')) {
        const initialMessage = await alice.initialiseSession(bobsBundle, 'bob');

        //bob receives key exchange
        await processMessage('alice', bob.Session, bob.Account, bob.Store, initialMessage as EncryptedMessage);
    }

    setInterval(async () => {
        let toSend = `messageToBobFromAlice${aliceCounter++}`;

        console.log(chalk.red(`alice Encrypts: ${toSend}`));
        let encryptedMessage = await encryptMessage(toSend, alice.Session, 'bob', alice.Store);

        let plaintext = null;
        //bob receives first proper message after key exchange
        console.log(chalk.rgb(255, 191, 0)(`bob receives from alice: ${JSON.stringify(encryptedMessage)}`));
        plaintext = await processMessage('alice', bob.Session, bob.Account, bob.Store, encryptedMessage);

        console.log(chalk.green(`bob Decrypts: ${plaintext}`));
        toSend = `messageToAliceFromBob${bobCounter++}`;

        encryptedMessage = await encryptMessage(toSend, bob.Session, 'alice', bob.Store);
        console.log(chalk.red(`bob Encrypts: ${toSend}`));

        console.log(chalk.rgb(255, 191, 0)(`alice receives: ${JSON.stringify(encryptedMessage)}`));
        plaintext = await processMessage('bob', alice.Session, alice.Account, alice.Store, encryptedMessage);
        console.log(chalk.green(`Alice Decrypts: ${plaintext}`));

    }, 2000);

})();