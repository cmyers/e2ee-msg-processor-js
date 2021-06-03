import { Account, Session, Utility } from '@matrix-org/olm';
import { LocalStorageStore } from './store';
import chalk from 'chalk';
import { EncryptedMessage } from './MessageManager';
import { Crypto } from "@peculiar/webcrypto";

const crypto = new Crypto();

interface Device {
    id: number;
    jid: string;
}

const PICKLED_ACCOUNT_ID = 'pickledAccountId';
const DEVICEIDS_PREFIX = 'deviceids/'
const PICKLED_SESSION_KEY_PREFIX = 'pickledSessionKey/';
const PICKLED_SESSION_PREFIX = 'pickledSession/';
const PICKLED_ACCOUNT = 'pickledAccount';
const IDENTITY_PREFIX = 'identity/';
const IDENTITY_KEY = 'identityKey';
const PUBLISHED_PREKEYS = 'published_prekeys';
const PREKEYS = 100;

interface PreKey {
    id: number,
    key: string
}

export interface Bundle {
    deviceId: number,
    ik: string;
    spks: string;
    spkId: number;
    spk: string;
    prekeys: Array<PreKey>
}

export const DEVICE_ID = 'deviceId';

export class SessionManager {
    private _sessions: Map<string, Session> = new Map<string, Session>();
    private _account: Account;
    private _store: LocalStorageStore;
    private _idKey: string;
    private _deviceId: number;
    private _jid: string;
    private _pickledAccountId: number;
    private _devices: Array<Device> = [];
    private _preKeys: Array<PreKey>;

    constructor(jid: string, storeName: string) {
        this._jid = jid;
        this._account = new Account();
        this._store = new LocalStorageStore(storeName);

        this._pickledAccountId = parseInt(this._store.get(PICKLED_ACCOUNT_ID)!);
        this._deviceId = parseInt(this._store.get(DEVICE_ID)!);
        this._preKeys = JSON.parse(this._store.get(PUBLISHED_PREKEYS)!);

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

    private updateOneTimeKeys() {
        const oneTimePreKeys = JSON.parse(this._account.one_time_keys()).curve25519;
        this._preKeys = Object.keys(oneTimePreKeys).map((x, i) => {
            return {
                id: i,
                key: oneTimePreKeys[x]
            }
        });
        this._store.set(PUBLISHED_PREKEYS, JSON.stringify(this._preKeys));
    }
    generatePreKeyBundle(): Bundle {
        const randomIds = crypto.getRandomValues(new Uint32Array(2));
        const signedPreKeyId = randomIds[0];
        this._account.generate_one_time_keys(PREKEYS);
        const signature = this._account.sign(signedPreKeyId + this._idKey);

        // TODO CLARIFY:
        //should be called once published to the server
        //this removes the ability to expose the keys so once is called we can't retrieve them, only add new keys and publish again
        //this logic needs to be checked, as we might not want to publish another bundle, only replace used keys and publish
        //this._account.mark_keys_as_published();

        this.updateOneTimeKeys();

        return {
            deviceId: this._deviceId,
            ik: this._idKey,
            spks: signature,
            spkId: signedPreKeyId,
            spk: JSON.parse(this._account.identity_keys()).ed25519,
            prekeys: this._preKeys
        };
    }

    //TODO add device if we don't have it (except our own?)
    updateDeviceIds(jid: string, deviceIds: Array<number>) {
        deviceIds.forEach(newDeviceId => {
            if(!this._devices.some(x => x.jid === jid && newDeviceId === x.id)) {
                this._devices.push({
                    id: newDeviceId,
                    jid
                })
            }
        });

        const devicesToUpdate = this._devices.filter(x => x.jid === jid);

        if(devicesToUpdate.length > 0) {
            this._store.set(`${DEVICEIDS_PREFIX}${jid}`, JSON.stringify(devicesToUpdate.map(x => x.id)));
        }
    }

    deviceIdsFor(jid: string): Array<number> {
        let devices = this._devices.filter(x => x.jid === jid).map(x => x.id);
        if (devices.length === 0) {
            const deviceIds = this._store.get(`${DEVICEIDS_PREFIX}${jid}`)!;
            devices = JSON.parse(deviceIds);
            if(devices?.length > 0) {
                this.updateDeviceIds(jid, devices);
            }
            return devices ? devices : [];
        }
        return devices;

    }

    getSession(jid: string, deviceId: number): Session | null {
        let session = this._sessions.get(`${jid}/${deviceId}`);

        if (!session) {
            return this.loadSession(jid, deviceId);
        }
        return session;
    }

    encryptKey(key: string, jid: string, deviceId: number) {
        const session = this.getSession(jid, deviceId)!;
        //TODO if session is null we need to create one right? or should we do this before this point?
        const encrypted = session.encrypt(key);
        this.pickleSession(jid, deviceId, session);
        return encrypted;
    }

    //TODO decrypt key from rid key
    //Get devices for each device from recipient and create a session for each if one doesn't exist
    async decryptKey(encryptedMessage: EncryptedMessage): Promise<string> {
        const key = encryptedMessage.header.keys.find(x => x.rid === this._deviceId)!;

        if (key === null) {
            throw new Error('No key found for this device');
        }

        let session = this.getSession(encryptedMessage.from, encryptedMessage.header.sid)!;

        //TO CHECK session.has_received_message() usage

        if (!session || !session.has_received_message() && key.type === 0) {
            session = await this.initialiseInboundSession(encryptedMessage); //This doesn't work if a session has already been initialised

            if (!session.matches_inbound(key.key_base64)) {
                throw new Error('Something went wrong establishing an inbound session');
            }
        }

        const decrypted = session.decrypt(key.type, key.key_base64);
        this.pickleSession(encryptedMessage.from, encryptedMessage.header.sid, session);
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
        if (!pickledSessionKey) {
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

    private async initialiseInboundSession(keyExchangeMessage: EncryptedMessage): Promise<Session> {
        const session = this.createSession(keyExchangeMessage.from, keyExchangeMessage.header.sid);
        const key = keyExchangeMessage.header.keys.find(x => x.rid === this.DeviceId)!;

        session.create_inbound(this._account, key.key_base64);

        this._account.remove_one_time_keys(session);
        this._account.generate_one_time_keys(1);
        this.updateOneTimeKeys();
        
        this._sessions.set(`${keyExchangeMessage.from}/${keyExchangeMessage.header.sid}`, session);
        this._store.set(PICKLED_ACCOUNT, this._account.pickle(this._pickledAccountId.toString()));
        this.pickleSession(keyExchangeMessage.from, keyExchangeMessage.header.sid, session);

        return session;
    }

    initialiseOutboundSession(jid: string, bundle: Bundle) {

        if (!this.verifyBundle(bundle)) {
            throw new Error('Bundle verification failed');
        }

        console.log(chalk.blue(`${this._jid}'s verified ${jid}'s identity`));

        const session = this.createSession(jid, bundle.deviceId);

        // TODO implement isTrusted
        this._store.set(`${IDENTITY_PREFIX}${jid}/${bundle.deviceId}`, bundle.ik);

        const otk_id = bundle.prekeys[crypto.getRandomValues(new Uint32Array(1))[0] % bundle.prekeys.length];

        console.log(chalk.blue(`${this._jid} gets ${jid}/${bundle.deviceId}'s prekey: ${otk_id.key}`));

        session.create_outbound(
            this._account, bundle.ik, otk_id.key
        );

        this._sessions.set(`${jid}/${bundle.deviceId}`, session);
        this._store.set(PICKLED_ACCOUNT, this._account.pickle(this._pickledAccountId.toString()));
        this.pickleSession(jid, bundle.deviceId, session);
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