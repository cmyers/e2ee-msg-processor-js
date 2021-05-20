import { Account, Session, Utility } from 'olm';
import { Crypto } from "@peculiar/webcrypto";
import { DataUtils, LocalStorageStore } from './store';
import chalk from 'chalk';

// TODO handle corrupt sessions - request new session logic if can't decrypt, informing sender to initialise a new session and resend message

const crypto = new Crypto();

const TAG_LENGTH = 128;

//storage constants
const PICKLED_ACCOUNT_ID = 'pickledAccountId';
const DEVICE_ID = 'deviceId';
const PICKLED_SESSION_KEY_PREFIX = 'pickledSessionKey/';
const PICKLED_SESSION_PREFIX = 'pickledSession/';
const PICKLED_ACCOUNT = 'pickledAccount';
const IDENTITY_PREFIX = 'identity/';
const IDENTITY_KEY = 'identityKey';
const PREKEYS = 100;

const KEY_ALGO = {
    'name': 'AES-GCM',
    'length': 128
};

interface Key {
    key_base64: string;
    type: number;
    rid: number;
}

export interface EncryptedMessage {
    jid: string,
    header: {
        sid: number
        keys: Array<Key>,
        iv_base64: string
    },
    payload_base64: string
};

export interface Bundle {
    deviceId: number,
    ik: string;
    spks: string;
    spkId: number;
    spk: string;
    prekeys: Array<{
        id: number;
        key: any;
    }>;
}

export class MessageManager {
    private _sessionManager: SessionManager;

    constructor(sessionManager: SessionManager) {
        this._sessionManager = sessionManager;
    }

    //TODO produce key for each deviceid
    async encryptMessage(jid: string, plaintext: string): Promise<EncryptedMessage> {
        const sid = parseInt(this._sessionManager.Store.get(DEVICE_ID)!);
        const deviceIds = this._sessionManager.deviceIdsFor(jid);
        const keys: Array<Key> = [];

        const iv = crypto.getRandomValues(new Uint8Array(12)),
        key = await crypto.subtle.generateKey(KEY_ALGO, true, ['encrypt', 'decrypt']),
        algo = {
            'name': 'AES-GCM',
            'iv': iv,
            'tagLength': TAG_LENGTH
        },
        encrypted = await crypto.subtle.encrypt(algo, key, DataUtils.stringToArrayBuffer(plaintext)),
        length = encrypted.byteLength - ((128 + 7) >> 3),
        ciphertext = encrypted.slice(0, length);

        for(let i in deviceIds) {
            const tag = encrypted.slice(length),
            exported_key = await crypto.subtle.exportKey('raw', key),
            key_tag = DataUtils.arrayBufferToBase64String(DataUtils.appendArrayBuffer(exported_key, tag)),
            encryptedKey = this._sessionManager.encryptKey(key_tag, jid, deviceIds[i]);

            keys.push({
                key_base64: (encryptedKey as any).body,
                rid: deviceIds[i],
                type: (encryptedKey as any).type
            });

        }

        return {
            jid: this._sessionManager.JID,
            header: {
                sid,
                iv_base64: DataUtils.arrayBufferToBase64String(iv),
                keys
            },
            payload_base64: DataUtils.arrayBufferToBase64String(ciphertext)
        }
    }

    private async decryptMessage(encryptedMessage: EncryptedMessage): Promise<string> {
        const decryptedKey = this._sessionManager.decryptKey(encryptedMessage);
        const key = DataUtils.base64StringToArrayBuffer(decryptedKey).slice(0, 16);
        const tag = DataUtils.base64StringToArrayBuffer(decryptedKey).slice(16);
        const key_obj = await crypto.subtle.importKey('raw', key, KEY_ALGO, true, ['encrypt', 'decrypt']);
        const cipher = DataUtils.appendArrayBuffer(DataUtils.base64StringToArrayBuffer(encryptedMessage.payload_base64), tag);

        const algo = {
            'name': 'AES-GCM',
            'iv': DataUtils.base64StringToArrayBuffer(encryptedMessage.header.iv_base64),
            'tagLength': TAG_LENGTH
        };

        const decryptedArrayBuffer = await crypto.subtle.decrypt(algo, key_obj, cipher);

        return DataUtils.arrayBufferToString(decryptedArrayBuffer);
    }

    // TODO handle decryption failure cases
    // - copy of already decrypted message - ignore decryption failure
    // - establish a new session with the sender (reverse session initialisation?)
    //TODO keep copy of last message sent in case of client decryption failure and session-re-establish attempt
    //TODO Message Carbons - XMPP layer?
    //TODO Message Archive - XMPP layer? 
    async processMessage(message: EncryptedMessage): Promise<string> {
        //TODO get session for each deviceid for this jid!
        let session = this._sessionManager.session(message.jid, message.header.sid);
        const key = message.header.keys.find(x => x.rid === this._sessionManager.DeviceId)!;

        if (!session && key.type === 0) {
            //TODO Idkey should be pulled from bundle for each device easlier on and stored as such to retreive here
            const idKey = this._sessionManager.Store.get(`${IDENTITY_PREFIX}${message.jid}/${message.header.sid}`);
            session = await this._sessionManager.initialiseInboundSession(message);

            if(idKey && !session.matches_inbound_from(idKey, key.key_base64)) {
                throw new Error('Message is from untrusted source')
            }

            const plaintext = await this.decryptMessage(message);
            return plaintext;
        } else {
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
            return await this.decryptMessage(message);
        }
    }
}

// TODO Need to manage a session per receiver, not one session for all!
export class SessionManager {
    private _sessions: Map<string, Session> = new Map<string, Session>();
    private _account: Account;
    private _store: LocalStorageStore;
    private _idKey: string;
    private _deviceId: number;
    private _jid: string;
    private _pickledAccountId: number;

    constructor(jid: string, storeName: string) {
        this._jid = jid;
        this._account = new Account();
        this._store = new LocalStorageStore(storeName);

        this._pickledAccountId = parseInt(this._store.get(PICKLED_ACCOUNT_ID)!);
        this._deviceId = parseInt(this._store.get(DEVICE_ID)!);

        const pickledAccount = this._store.get(PICKLED_ACCOUNT);

        if (pickledAccount && this._pickledAccountId && this._deviceId) {
            this._account.unpickle(this._pickledAccountId.toString(), pickledAccount);
        } else {
            const randValues = crypto.getRandomValues(new Uint32Array(2));
            this._account.create();
            this._pickledAccountId = randValues[0];
            this._deviceId = randValues[1];
            this._store.set(PICKLED_ACCOUNT_ID, this._pickledAccountId);
            this._store.set(DEVICE_ID, this._deviceId);
            this._store.set(PICKLED_ACCOUNT, this._account.pickle(this._pickledAccountId.toString()));
        }

        this._idKey = JSON.parse(this._account.identity_keys()).curve25519;
        this._store.set(IDENTITY_KEY, this._idKey);
    }

    // private refillPreKeys(bundle: Bundle, session: Session): Bundle {
    //     const test = this._account.remove_one_time_keys(session);
    //     this._account.generate_one_time_keys(1);
    //     //bundle.prekeys.map
    //     this._account.mark_keys_as_published();
    //     return bundle;
    // }

    // The first thing that needs to happen if a client wants to
        // start using OMEMO is they need to generate an IdentityKey
        // and a Device ID. The IdentityKey is a Curve25519 [6]
        // public/private Key pair. The Device ID is a randomly
        // generated integer between 1 and 2^31 - 1.
        
    // Handle regenerating used keys
    generatePreKeyBundle(): Bundle {
        const randomIds = crypto.getRandomValues(new Uint32Array(2));
        const signedPreKeyId = randomIds[0];
        this._account.generate_one_time_keys(PREKEYS);
        const oneTimePreKeys = JSON.parse(this._account.one_time_keys()).curve25519;  
        const signature = this._account.sign(signedPreKeyId + this._idKey);

        // TODO CLARIFY:
        //should be called once published to the server
        //this removes the ability to expose the keys so once is called we can't retrieve them, only add new keys and publish again
        //this logic needs to be checked, as we might not want to publish another bundle, only replace used keys and publish
        //this._account.mark_keys_as_published();

        return {
            deviceId: this._deviceId,
            ik: this._idKey,
            spks: signature,
            spkId: signedPreKeyId,
            spk: JSON.parse(this._account.identity_keys()).ed25519,
            prekeys: Object.keys(oneTimePreKeys).map((x, i) => {
                return {
                    id: i,
                    key: oneTimePreKeys[x]
                }
            })
        }
    }

    deviceIdsFor(jid: string): Array<number> {
        const deviceIds = this.Store.itemsContaining(`${PICKLED_SESSION_PREFIX}${jid}`);
        return deviceIds.map(x => parseInt(x.match(/[^/]+$/)![0]));
    }

    session(jid: string, deviceId: number): Session | null {
        let session = this._sessions.get(`${jid}/${deviceId}`);

        if(!session) {
            return this.loadSession(jid, deviceId);
        }
        return session;
    }

    encryptKey(key: string, jid: string, deviceId: number) {
        const session = this.session(jid, deviceId)!;
        const encrypted = session.encrypt(key);
        this.pickleSession(jid, deviceId, session);
        return encrypted;
    }

    //TODO decrypt key from rid key
    decryptKey(encryptedMessage: EncryptedMessage) {
        const session = this.session(encryptedMessage.jid, encryptedMessage.header.sid)!;
        const key = encryptedMessage.header.keys.find(x => x.rid === this.DeviceId)!;
        const decrypted = session.decrypt(key.type, key.key_base64);
        this.pickleSession(encryptedMessage.jid, encryptedMessage.header.sid, session);
        return decrypted;
    }

    get Account(): Account {
        return this._account;
    }

    get Store(): LocalStorageStore {
        return this._store;
    }

    get JID(): string {
        return this._jid;
    }

    get DeviceId(): number {
        return this._deviceId;
    }

    get IdentityKey(): string {
        return this._idKey!;
    }

    private loadSession(jid: string, deviceId: number): Session | null {
        const session = new Session();

        const pickledSessionKey = this._store.get(`${PICKLED_SESSION_KEY_PREFIX}${jid}/${deviceId}`);
        const pickledSession = this._store.get(`${PICKLED_SESSION_PREFIX}${jid}/${deviceId}`);

        if (pickledSession) {
            console.log(chalk.blue(`Load ${this._jid}'s session with ${jid}/${deviceId}: ${pickledSession}`));
            session.unpickle(pickledSessionKey!, pickledSession);
            this._sessions.set(`${jid}/${deviceId}`, session);

            return session;
        }
        return null;
    }

    private pickleSession(jid: string, deviceId: number, session: Session) {
        let pickledSessionKey = this._store.get(`${PICKLED_SESSION_KEY_PREFIX}${jid}/${deviceId}`);
        if(!pickledSessionKey) {
            const randValues = crypto.getRandomValues(new Uint32Array(1));
            pickledSessionKey = randValues[0].toString();
            this._store.set(`${PICKLED_SESSION_KEY_PREFIX}${jid}/${deviceId}`, pickledSessionKey);
        }

        this._store.set(`${PICKLED_SESSION_PREFIX}${jid}/${deviceId}`, session.pickle(pickledSessionKey));
    }

    private createSession(jid: string, deviceId: number): Session {
        const session = new Session();
        this.pickleSession(jid, deviceId, session);
        return session;
    }

    async initialiseInboundSession(keyExchangeMessage: EncryptedMessage): Promise<Session> {
        const session = this.createSession(keyExchangeMessage.jid, keyExchangeMessage.header.sid);
        const key = keyExchangeMessage.header.keys.find(x => x.rid === this.DeviceId)!;

        session.create_inbound(this._account, key.key_base64);
        //TODO get identity from bundle for the device id if we don't have it yet!
        //session.create_inbound_from(this._account, idkey from sender's device bundle, keyExchangeMessage.key_base64);

        this._account.remove_one_time_keys(session);
        this._account.generate_one_time_keys(1);
        //this._account.mark_keys_as_published(); //see generatedPreKeyBundle

        this._sessions.set(`${keyExchangeMessage.jid}/${keyExchangeMessage.header.sid}`, session);
        this._store.set(PICKLED_ACCOUNT, this._account.pickle(this._pickledAccountId.toString()));  
        this.pickleSession(keyExchangeMessage.jid, keyExchangeMessage.header.sid, session);

        return session;
    }

    async initialiseOutboundSession(jid: string, bundle: Bundle): Promise<Session> {

        if (!this.verifyBundle(bundle)) {
            throw new Error('Bundle verification failed');
        }

        console.log(chalk.blue(`${this._jid}'s verified ${jid}'s identity`));

        const session = this.createSession(jid, bundle.deviceId);

        // TODO implement isTrusted
        this._store.set(`${IDENTITY_PREFIX}${jid}/${bundle.deviceId}`, bundle.ik);

         //TODO PreKey management
         // - refill keys after one time use
         //storePrekey used, does the sender or receiver store this?
        const otk_id = bundle.prekeys[crypto.getRandomValues(new Uint32Array(1))[0] % 5];

        console.log(chalk.blue(`${this._jid} gets ${jid}/${bundle.deviceId}'s prekey: ${otk_id.key}`));

        session.create_outbound(
            this._account, bundle.ik, otk_id.key
        );

        this._sessions.set(`${jid}/${bundle.deviceId}`, session);
        this._store.set(PICKLED_ACCOUNT, this._account.pickle(this._pickledAccountId.toString()));  
        this.pickleSession(jid, bundle.deviceId, session);

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