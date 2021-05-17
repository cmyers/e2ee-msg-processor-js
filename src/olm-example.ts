import { Account, init as olmInit, Session, Utility } from 'olm';
import { Crypto } from "@peculiar/webcrypto";
import { DataUtils, LocalStorageStore } from './store/store';
import chalk from 'chalk';

// TODO handle corrupt sessions - request new session logic if can't decrypt, informing sender to initialise a new session and resend message

const crypto = new Crypto();

const TAG_LENGTH = 128;

//storage constants
const PICKLED_ACCOUNT_ID = 'pickledAccountId';
const PICKLED_SESSION_KEY_PREFIX = 'pickledSessionKey/';
const PICKLED_SESSION_PREFIX = 'pickledSession/';
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

// TODO move into SessionManager
function getBundle(idKey: string, account: Account): Bundle {
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

class MessageManager {
    private _sessionManager: SessionManager;

    constructor(sessionManager: SessionManager) {
        this._sessionManager = sessionManager;
    }

    async encryptMessage(jid: string, plaintext: string): Promise<EncryptedMessage> {
        const rid = this._sessionManager.Store.get(`${IDENTITY_PREFIX}${jid}`) as string;
        const sid = this._sessionManager.Store.get(IDENTITY_KEY) as string;
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

        const encryptedKey = this._sessionManager.encryptKey(key_tag, jid);

        return {
            rid,
            sid,
            iv_base64: DataUtils.arrayBufferToBase64String(iv),
            key_base64: (encryptedKey as any).body,
            payload_base64: DataUtils.arrayBufferToBase64String(ciphertext),
            type: (encryptedKey as any).type
        }
    }
    private async decryptMessage(jid: string, encryptedMessage: EncryptedMessage): Promise<string> {
        const decryptedKey = this._sessionManager.decryptKey(encryptedMessage, jid);
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

    async processMessage(jid: string, message: EncryptedMessage): Promise<string> {
        let session = this._sessionManager.session(jid);

        // check session manager for an existing session. If does not exist then create new inbound session

        if (!session && message.type === 0) {

            session = await this._sessionManager.initialiseInboundSession(jid, message); // LAST CODE - create inbound session logic
            // if we have never received messages by this point something has gone wrong - this might be a situation that happened before re-write but below is still relevant
            // TODO handle this case before decryptiong? How? Ask sender for a new session key exchange? What is the protocol? See below.

            const plaintext = await this.decryptMessage(jid, message);

            this._sessionManager.Account.remove_one_time_keys(session);
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
            return await this.decryptMessage(jid, message);
        }
    }
}

// TODO Need to manage a session per receiver, not one session for all!
class SessionManager {
    private _sessions: Map<string, Session> = new Map<string, Session>();
    private _account: Account;
    private _store: LocalStorageStore;
    private _idKey: string | null = null;
    private _jid: string;
    private _pickledAccountId: string | null = null;
    private _initialised: boolean = false;

    constructor(jid: string) {
        this._jid = jid;
        this._store = new LocalStorageStore(jid);
        this._account = new Account();

        this._pickledAccountId = this._store.get(PICKLED_ACCOUNT_ID);

        const pickledAccount = this._store.get(PICKLED_ACCOUNT);

        if (pickledAccount && this._pickledAccountId) {
            this._account.unpickle(this._pickledAccountId, pickledAccount);
        } else {
            const randValues = crypto.getRandomValues(new Uint32Array(1));
            this._account.create();
            this._pickledAccountId = randValues[0].toString();
            this._store.set(PICKLED_ACCOUNT_ID, this._pickledAccountId);
            this._store.set(PICKLED_ACCOUNT, this._account.pickle(this._pickledAccountId));
        }

        this._idKey = JSON.parse(this._account.identity_keys()).curve25519;
        this._store.set(IDENTITY_KEY, this._idKey);
    }

    session(jid: string): Session | null {
        let session = this._sessions.get(jid);

        if(!session) {
            return this.loadSession(jid);
        }
        return session;
    }

    encryptKey(key: string, jid: string) {
        const session = this.session(jid) as Session;
        const encrypted = session.encrypt(key);
        this.pickleSession(jid, session);
        return encrypted;
    }

    decryptKey(encryptedMessage: EncryptedMessage, jid: string) {
        const session = this.session(jid) as Session;
        const decrypted = session.decrypt(encryptedMessage.type, encryptedMessage.key_base64);
        this.pickleSession(jid, session);
        this._store.set(`${IDENTITY_PREFIX}${jid}`, encryptedMessage.sid);
        return decrypted;
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

    private loadSession(jid: string): Session | null {
        const session = new Session();

        const pickledSessionKey = this._store.get(`${PICKLED_SESSION_KEY_PREFIX}${jid}`);
        const pickledSession = this._store.get(`${PICKLED_SESSION_PREFIX}${jid}`);

        if (pickledSession) {
            console.log(chalk.blue(`Load ${this._jid}'s session with ${jid}: ${pickledSession}`));
            session.unpickle(pickledSessionKey as string, pickledSession);
            this._sessions.set(jid, session);

            return session;
        }
        return null;
    }

    private pickleSession(jid: string, session: Session) {
        let pickledSessionSecret = this._store.get(`${PICKLED_SESSION_KEY_PREFIX}${jid}`);
        if(!pickledSessionSecret) {
            const randValues = crypto.getRandomValues(new Uint32Array(1));
            pickledSessionSecret = randValues[0].toString();
            this._store.set(`${PICKLED_SESSION_KEY_PREFIX}${jid}`, pickledSessionSecret);
        }

        this._store.set(`${PICKLED_SESSION_PREFIX}${jid}`, session.pickle(pickledSessionSecret));
    }

    private createSession(jid: string): Session {
        const session = new Session();
        this.pickleSession(jid, session);
        return session;
    }

    async initialiseInboundSession(jid: string, keyExchangeMessage: EncryptedMessage): Promise<Session> {
        const session = this.createSession(jid);
        session.create_inbound(this._account, keyExchangeMessage.key_base64);

        this._sessions.set(jid, session);
        this._store.set(PICKLED_ACCOUNT, this._account.pickle(this._pickledAccountId as string));  
        this.pickleSession(jid, session);

        return session;
    }

    async initialiseOutboundSession(jid: string, bundle: Bundle): Promise<Session> {

        if (!this.verifyBundle(bundle)) {
            throw new Error('Bundle verification failed');
        }

        console.log(chalk.blue(`${this._jid}'s verified ${jid}'s identity`));

        const session = this.createSession(jid);

        // TODO implement isTrusted
        this._store.set(`${IDENTITY_PREFIX}${jid}`, bundle.ik);

        const otk_id = bundle.prekeys[0]; //Grab a random key

        console.log(chalk.blue(`${this._jid} gets ${jid}'s prekey: ${otk_id.key}`));

        session.create_outbound(
            this._account, bundle.ik, otk_id.key
        );

        this._sessions.set(jid, session);
        this._store.set(PICKLED_ACCOUNT, this._account.pickle(this._pickledAccountId as string));  
        this.pickleSession(jid, session);

        return session;
    }

    private async verifyBundle(bundle: Bundle): Promise<boolean> {
        try {
            const u = new Utility();
            u.ed25519_verify(bundle.spk, bundle.spkId + bundle.ik, bundle.spks);
            u.free();
            return true;
        } catch (e) {
            // handle an untrusted bundle
            return false;
        }
    }
}

(async () => {
    await olmInit();
    const aliceSessionManager = new SessionManager('alice');
    const aliceMsgManager = new MessageManager(aliceSessionManager);

    const bobSessionManager = new SessionManager('bob');
    const bobMsgManager = new MessageManager(bobSessionManager);

    const charlieSessionManager = new SessionManager('charlie');
    const charlieMsgManager = new MessageManager(charlieSessionManager);

    //session init

    const bobsBundle = getBundle(bobSessionManager.IdentityKey, bobSessionManager.Account);
    console.log(chalk.rgb(255, 191, 0)(`Alice gets Bob's bundle: ${JSON.stringify(bobsBundle)}`));


    if (!aliceSessionManager.session('bob')) {
        await aliceSessionManager.initialiseOutboundSession('bob', bobsBundle);
        const initialMessage = await aliceMsgManager.encryptMessage('bob', '');

        //bob receives key exchange
        await bobMsgManager.processMessage('alice', initialMessage as EncryptedMessage);
    }

    const charliesBundle = getBundle(charlieSessionManager.IdentityKey, charlieSessionManager.Account);
    console.log(chalk.rgb(255, 191, 0)(`Alice gets Charlie's bundle: ${JSON.stringify(charliesBundle)}`));

    if (!aliceSessionManager.session('charlie')) {
        await aliceSessionManager.initialiseOutboundSession('charlie', charliesBundle);
        const initialMessage = await aliceMsgManager.encryptMessage('charlie', '');

        //charlie receives key exchange
        await charlieMsgManager.processMessage('alice', initialMessage as EncryptedMessage);
    }

    let aliceCounter = 0;
    let bobCounter = 0;
    let charlieCounter = 0;

    setInterval(async () => {
        let toSend = `messageToBobFromAlice${aliceCounter++}`;

        console.log(chalk.red(`alice Encrypts: ${toSend}`));
        let encryptedMessage = await aliceMsgManager.encryptMessage('bob', toSend);

        let plaintext = null;
        //bob receives first proper message after key exchange
        console.log(chalk.rgb(255, 191, 0)(`bob receives from alice: ${JSON.stringify(encryptedMessage)}`));
        plaintext = await bobMsgManager.processMessage('alice', encryptedMessage);

        console.log(chalk.green(`bob Decrypts: ${plaintext}`));
        toSend = `messageToAliceFromBob${bobCounter++}`;

        encryptedMessage = await bobMsgManager.encryptMessage('alice', toSend);
        console.log(chalk.red(`bob Encrypts: ${toSend}`));

        console.log(chalk.rgb(255, 191, 0)(`alice receives from bob: ${JSON.stringify(encryptedMessage)}`));
        plaintext = await aliceMsgManager.processMessage('bob', encryptedMessage);
        console.log(chalk.green(`Alice Decrypts: ${plaintext}`));

        toSend = `messageToCharlieFromAlice${aliceCounter++}`;

        console.log(chalk.red(`alice Encrypts: ${toSend}`));
        encryptedMessage = await aliceMsgManager.encryptMessage('charlie', toSend);
        //bob receives first proper message after key exchange
        console.log(chalk.rgb(255, 191, 0)(`charlie receives from alice: ${JSON.stringify(encryptedMessage)}`));
        plaintext = await charlieMsgManager.processMessage('alice', encryptedMessage);

        console.log(chalk.green(`charlie Decrypts: ${plaintext}`));

        if(aliceCounter%5 === 0) {
            toSend = `messageToAliceFromCharlie${charlieCounter++}`;

            encryptedMessage = await charlieMsgManager.encryptMessage('alice', toSend);
            console.log(chalk.red(`charlie Encrypts: ${toSend}`));

            console.log(chalk.rgb(255, 191, 0)(`alice receives from charlie: ${JSON.stringify(encryptedMessage)}`));
            plaintext = await aliceMsgManager.processMessage('charlie', encryptedMessage);
            console.log(chalk.green(`Alice Decrypts: ${plaintext}`));
        }

    }, 2000);

})();