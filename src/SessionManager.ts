import { Account, Session, Utility } from '@matrix-org/olm';
import chalk from 'chalk';
import { Crypto } from "@peculiar/webcrypto";
import { NamespacedLocalStorage } from './NamespacedLocalStorage';
import { LocalStorage } from './LocalStorage';
import { Bundle } from './Bundle';
import { EncryptedMessage } from './EncryptedMessage';
import { PreKey } from './PreKey';
import EventEmitter from 'events';

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
const PREKEYS = 100;

export interface EncryptedKey {
    body: string,
    type: number
}

export const DEVICE_ID = 'deviceId';

export class SessionManager {
    private readonly _sessionEvents = new EventEmitter();
    private readonly _jid: string;
    private readonly _sessions: Map<string, Session> = new Map<string, Session>();
    private readonly _account: Account;
    private readonly _store: NamespacedLocalStorage;
    private readonly _idKey: string;
    private readonly _deviceId: number;
    private readonly _pickledAccountId: number;
    private _devices: Array<Device> = [];

    constructor(jid: string, localStorage: LocalStorage) {
        this._jid = jid;
        this._account = new Account();
        this._store = new NamespacedLocalStorage(localStorage, jid);

        const pickledAccountId = this._store.get(PICKLED_ACCOUNT_ID);
        const deviceId = this._store.get(DEVICE_ID);
        const pickledAccount = this._store.get(PICKLED_ACCOUNT);

        if (pickledAccount && pickledAccountId && deviceId) {
            this._pickledAccountId = parseInt(pickledAccountId);
            this._deviceId = parseInt(deviceId);
            this._account.unpickle(this._pickledAccountId.toString(), pickledAccount);
        } else {
            const randValues = crypto.getRandomValues(new Uint32Array(2));
            this._account.create();
            this._pickledAccountId = randValues[0];
            this._deviceId = randValues[1];
            this._store.set(PICKLED_ACCOUNT_ID, this._pickledAccountId.toString());
            this._store.set(DEVICE_ID, this._deviceId.toString());
            this._store.set(PICKLED_ACCOUNT, this._account.pickle(this._pickledAccountId.toString()));
        }

        this._idKey = JSON.parse(this._account.identity_keys()).curve25519;
        this._store.set(IDENTITY_KEY, this._idKey);
    }

    private getPreKeys(): PreKey[] {
        const oneTimePreKeys = JSON.parse(this._account.one_time_keys()).curve25519;
        return Object.keys(oneTimePreKeys).map((x, i) => {
            return {
                id: i,
                key: oneTimePreKeys[x]
            }
        });
    }

    getPreKeyBundle(): Bundle {
        const randomIds = crypto.getRandomValues(new Uint32Array(2));
        const signedPreKeyId = randomIds[0];
        const oneTimePreKeys = this.getPreKeys();
        if(oneTimePreKeys.length === 0) {
            this._account.generate_one_time_keys(PREKEYS);
        }
        const signature = this._account.sign(signedPreKeyId + this._idKey);

        return {
            deviceId: this._deviceId,
            ik: this._idKey,
            spks: signature,
            spkId: signedPreKeyId,
            spk: JSON.parse(this._account.identity_keys()).ed25519,
            prekeys: this.getPreKeys()
        };
    }

    updateDeviceIds(jid: string, deviceIds: Array<number>): void {
        const newDeviceList = this._devices.filter(x => x.jid !== jid);

        deviceIds.forEach(newDeviceId => {
            newDeviceList.push({
                id: newDeviceId,
                jid
            })
        });

        this._devices = newDeviceList;
        this._store.set(`${DEVICEIDS_PREFIX}${jid}`, JSON.stringify(deviceIds));
    }

    deviceIdsFor(jid: string): Array<number> {
        let devices = this._devices.filter(x => x.jid === jid).map(x => x.id);
        if (devices.length === 0) {
            const deviceIds = this._store.get(`${DEVICEIDS_PREFIX}${jid}`);
            devices = deviceIds ? JSON.parse(deviceIds) : [];
            if (devices?.length > 0) {
                this.updateDeviceIds(jid, devices);
            }
            return devices ? devices : [];
        }
        return devices;
    }

    getSession(jid: string, deviceId: number, current: boolean): Session | null {
        const session = this._sessions.get(`${jid}/${deviceId}/${current ? 'current' : 'old'}`);
        console.log(this._jid, 'gets Current Session', jid, deviceId, current, session);

        if (!session) {
            return this.loadSession(jid, deviceId, current);
        }
        
        return session;
    }

    onSessionInitialised(cb: (jid: string) => void): void {
        this._sessionEvents.removeAllListeners();
        this._sessionEvents.on('sessionInitialised', (jid) => cb(jid));
    }

    onBundleUpdated(cb: (bundle: Bundle) => void): void {
        this._sessionEvents.removeAllListeners();
        this._sessionEvents.on('bundleUpdated', (bundle) => cb(bundle));
    }

    encryptKey(key: string, jid: string, deviceId: number): EncryptedKey {
        const session = this.getSession(jid, deviceId, true);
        if (!session) {
            throw new Error(`Missing session for JID: ${jid} DeviceId: ${deviceId}`);
        }
        const encrypted = session.encrypt(key);
        this.pickleSession(jid, deviceId, session, true);
        return encrypted as EncryptedKey;
    }

    async decryptKey(encryptedMessage: EncryptedMessage): Promise<string | null> {
        const key = encryptedMessage.header.keys.find(x => x.rid === this._deviceId);

        if (key == null) {
            return null;
        }

        const currentSession = this.getSession(encryptedMessage.from, encryptedMessage.header.sid, true);

        try {
            if (key.type === 0) {
                if(currentSession && currentSession.matches_inbound(key.key_base64)) {
                    const decrypted = currentSession.decrypt(key.type, key.key_base64);
                    this.pickleSession(encryptedMessage.from, encryptedMessage.header.sid, currentSession, true);
                    return decrypted;
                } else {
                    if(currentSession) {
                        this.pickleSession(encryptedMessage.from, encryptedMessage.header.sid, currentSession, false);
                    }
                    
                    const session = this.createSession(encryptedMessage.from, encryptedMessage.header.sid);
                    session.create_inbound(this._account, key.key_base64);
                    this._store.set(PICKLED_ACCOUNT, this._account.pickle(this._pickledAccountId.toString()));

                    this._account.remove_one_time_keys(session);
                    this._account.generate_one_time_keys(1);
                    const bundle = this.getPreKeyBundle();
                    this._sessionEvents.emit('bundleUpdated', bundle);

                    const decrypted = session.decrypt(key.type, key.key_base64);
                    this.pickleSession(encryptedMessage.from, encryptedMessage.header.sid, session, true);
                    return decrypted;
                }
            } else {
                if (currentSession) {
                    const decrypted = currentSession.decrypt(key.type, key.key_base64);
                    this.pickleSession(encryptedMessage.from, encryptedMessage.header.sid, currentSession, true);
                    return decrypted;
                } else {
                    throw new Error(`No current session`);
                }
            }
            
        } catch (e) {
            const oldSession = this.getSession(encryptedMessage.from, encryptedMessage.header.sid, false);
            if(oldSession) {
                const decrypted = oldSession.decrypt(key.type, key.key_base64);
                this.pickleSession(encryptedMessage.from, encryptedMessage.header.sid, oldSession, true);
                if(currentSession) {
                    this.pickleSession(encryptedMessage.from, encryptedMessage.header.sid, currentSession, false);
                }
                return decrypted;
            }
            throw new Error(`No old session to use`);
        }
    }

    get Account(): Account {
        return this._account;
    }

    get Store(): NamespacedLocalStorage {
        return this._store;
    }

    get JID(): string {
        return this._jid;
    }

    get DeviceId(): number {
        return this._deviceId;
    }

    get IdentityKey(): string {
        return this._idKey;
    }

    private loadSession(jid: string, deviceId: number, current: boolean): Session | null {
        console.log(`loading session from storage`, jid, deviceId);
        const pickledSessionKey = this._store.get(`${PICKLED_SESSION_KEY_PREFIX}${jid}/${deviceId}/${current ? 'current' : 'old'}`);
        const pickledSession = this._store.get(`${PICKLED_SESSION_PREFIX}${jid}/${deviceId}/${current ? 'current' : 'old'}`);

        if (pickledSessionKey && pickledSession) {
            const session = new Session();
            console.log(chalk.blue(`Load ${this._jid}'s ${current ? 'current' : 'old'} session with ${jid}/${deviceId}: ${pickledSession}`));
            session.unpickle(pickledSessionKey, pickledSession);
            this._sessions.set(`${jid}/${deviceId}/${current ? 'current' : 'old'}`, session);
            return session;
        }
        return null;
    }

    // private deleteSession(jid: string, deviceId: number): void {
    //     this._store.remove(`${PICKLED_SESSION_KEY_PREFIX}${jid}/${deviceId}`);
    //     this._store.remove(`${PICKLED_SESSION_PREFIX}${jid}/${deviceId}`);
    //     this._sessions.delete(`${jid}/${deviceId}`);
    // }

    private pickleSession(jid: string, deviceId: number, session: Session, current: boolean) { 
        let pickledSessionKey = this._store.get(`${PICKLED_SESSION_KEY_PREFIX}${jid}/${deviceId}/${current ? 'current' : 'old'}`);
        if (!pickledSessionKey) {
            const randValues = crypto.getRandomValues(new Uint32Array(1));
            pickledSessionKey = randValues[0].toString();
            this._store.set(`${PICKLED_SESSION_KEY_PREFIX}${jid}/${deviceId}/${current ? 'current' : 'old'}`, pickledSessionKey);
        }
        this._store.set(`${PICKLED_SESSION_PREFIX}${jid}/${deviceId}/${current ? 'current' : 'old'}`, session.pickle(pickledSessionKey));
        this._sessions.set(`${jid}/${deviceId}/${current ? 'current' : 'old'}`, session);
    }

    private createSession(jid: string, deviceId: number): Session {
        const session = new Session();
        this.pickleSession(jid, deviceId, session, true);
        return session;
    }

    initialiseOutboundSession(jid: string, bundle: Bundle): void {

        if (!this.verifyBundle(bundle)) {
            throw new Error('Bundle verification failed');
        }

        console.log(chalk.blue(`${this._jid} verified ${jid}'s identity`));

        const session = this.createSession(jid, bundle.deviceId);

        // TODO implement isTrusted
        this._store.set(`${IDENTITY_PREFIX}${jid}/${bundle.deviceId}`, bundle.ik);

        const otk_id = bundle.prekeys[crypto.getRandomValues(new Uint32Array(1))[0] % bundle.prekeys.length];

        console.log(chalk.blue(`${this._jid} gets ${jid}/${bundle.deviceId}'s prekey: ${otk_id.key}`));

        session.create_outbound(
            this._account, bundle.ik, otk_id.key
        );

        this._store.set(PICKLED_ACCOUNT, this._account.pickle(this._pickledAccountId.toString()));
        this.pickleSession(jid, bundle.deviceId, session, true);
    }

    private async verifyBundle(bundle: Bundle): Promise<boolean> {
        try {
            const u = new Utility();
            u.ed25519_verify(bundle.spk, bundle.spkId + bundle.ik, bundle.spks);
            u.free();
            return true;
        } catch (e) {
            //TODO handle an untrusted bundle
            return false;
        }
    }
}