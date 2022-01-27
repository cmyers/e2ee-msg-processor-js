import { Account, Session, Utility } from '@matrix-org/olm';
import chalk from 'chalk';
import { Crypto } from "@peculiar/webcrypto";
import { NamespacedLocalStorage } from './NamespacedLocalStorage';
import { AsyncStorage } from './AsyncStorage';
import { Bundle } from './Bundle';
import { EncryptedMessage } from './EncryptedMessage';
import { PreKey } from './PreKey';
import EventEmitter from 'events';
import { EncryptedKey } from './EncryptedKey';
import { DEVICE_ID } from './SharedConstants';

export class SessionManager {
    private readonly _sessionEvents = new EventEmitter();
    private readonly _jid: string;
    private readonly _sessions: Map<string, Session> = new Map<string, Session>();
    private readonly _account: Account;
    private readonly _store: NamespacedLocalStorage;
    private _idKey: string | undefined;
    private _deviceId: number | undefined;
    private _pickledAccountId: number | undefined;
    private _devices: Map<string, Array<number>>= new Map<string, Array<number>>();
    private readonly crypto = new Crypto();

    private readonly PICKLED_ACCOUNT_ID = 'pickledAccountId';
    private readonly DEVICEIDS_PREFIX = 'deviceids/'
    private readonly PICKLED_SESSION_KEY_PREFIX = 'pickledSessionKey/';
    private readonly PICKLED_SESSION_PREFIX = 'pickledSession/';
    private readonly PICKLED_ACCOUNT = 'pickledAccount';
    private readonly IDENTITY_PREFIX = 'identity/';
    private readonly IDENTITY_KEY = 'identityKey';
    private readonly BUNDLE_SPKS = 'BUNDLE_SPKS';
    private readonly BUNDLE_SPKID = 'BUNDLE_SPKID';
    private readonly PREKEYS = 100;

    constructor(jid: string, localStorage: AsyncStorage) {
        this._jid = jid;
        this._account = new Account();
        this._store = new NamespacedLocalStorage(localStorage, jid);
    }

    private async init() {
        const pickledAccountId = await this._store.get(this.PICKLED_ACCOUNT_ID);
        const deviceId = await this._store.get(DEVICE_ID);
        const pickledAccount = await this._store.get(this.PICKLED_ACCOUNT);

        if (pickledAccount && pickledAccountId && deviceId) {
            this._pickledAccountId = parseInt(pickledAccountId);
            this._deviceId = parseInt(deviceId);
            console.log('unpickling account');
            this._account.unpickle(this._pickledAccountId.toString(), pickledAccount);
            console.log(this.getPreKeys());
        } else {
            const randValues = this.crypto.getRandomValues(new Uint32Array(2));
            console.log('created new account');
            this._account.create();
            this._pickledAccountId = randValues[0];
            this._deviceId = randValues[1];
            await this._store.set(this.PICKLED_ACCOUNT_ID, this._pickledAccountId.toString());
            await this._store.set(DEVICE_ID, this._deviceId.toString());
            await this._store.set(this.PICKLED_ACCOUNT, this._account.pickle(this._pickledAccountId.toString()));
        }

        this._idKey = JSON.parse(this._account.identity_keys()).curve25519;
        await this._store.set(this.IDENTITY_KEY, this._idKey as string);
    }

    async generatePreKeyBundle(): Promise<Bundle> {
        console.log('getprekeybundle called');
        const randomIds = this.crypto.getRandomValues(new Uint32Array(2));
        const signedPreKeyId = randomIds[0];
        const oneTimePreKeys = this.getPreKeys();
        if (oneTimePreKeys.length === 0) {
            this._account.generate_one_time_keys(this.PREKEYS);
        }
        const signature = this._account.sign(signedPreKeyId + (this._idKey as string));

        await this._store.set(this.PICKLED_ACCOUNT, this._account.pickle((this._pickledAccountId as number).toString()));
        await this._store.set(this.BUNDLE_SPKS, signature);
        await this._store.set(this.BUNDLE_SPKID, signedPreKeyId.toString());

        return {
            deviceId: this._deviceId as number,
            ik: this._idKey as string,
            spks: signature,
            spkId: signedPreKeyId,
            spk: JSON.parse(this._account.identity_keys()).ed25519,
            prekeys: this.getPreKeys()
        };
    }

    async updateDeviceIds(jid: string, newDeviceIds: Array<number>): Promise<void> {
        newDeviceIds = [...new Set(newDeviceIds.concat(await this.deviceIdsFor(jid)))];
        console.log('newdevices:', newDeviceIds);
        this._devices.set(jid, newDeviceIds);+
        await this._store.set(`${this.DEVICEIDS_PREFIX}${jid}`, JSON.stringify(newDeviceIds));
    }

    async deviceIdsFor(jid: string): Promise<Array<number>> {
        let deviceIds = this._devices.get(jid);

        if(!deviceIds) {
            //TODO refresh the device ids from the server first, these could be out of date!
            const retrievedIds = await this._store.get(`${this.DEVICEIDS_PREFIX}${jid}`);
            if(retrievedIds) {
                deviceIds =  JSON.parse(retrievedIds);
            }
        }

        return deviceIds ? deviceIds : [];
    }

    async getSession(jid: string, deviceId: number, current: boolean): Promise<Session | null> {
        const session = this._sessions.get(`${jid}/${deviceId}/${current ? 'current' : 'old'}`);
        console.log(this._jid, 'gets Current Session', jid, deviceId, current, session);

        if (!session) {
            return await this.loadSession(jid, deviceId, current);
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

    async encryptKey(key: string, jid: string, deviceId: number): Promise<EncryptedKey> {
        const session = await this.getSession(jid, deviceId, true);
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
            throw new Error(`No key for ${this._deviceId}`);
        }

        const currentSession = await this.getSession(encryptedMessage.from, encryptedMessage.header.sid, true);

        try {
            if (key.type === 0) {
                if (currentSession && currentSession.matches_inbound(key.key_base64)) {
                    console.log('matches inbound');
                    const decrypted = currentSession.decrypt(key.type, key.key_base64);
                    this.pickleSession(encryptedMessage.from, encryptedMessage.header.sid, currentSession, true);
                    return decrypted;
                } else {
                    if (currentSession) {
                        this.pickleSession(encryptedMessage.from, encryptedMessage.header.sid, currentSession, false);
                    }

                    const session = this.createSession(encryptedMessage.from, encryptedMessage.header.sid);
                    session.create_inbound(this._account, key.key_base64);

                    this._account.remove_one_time_keys(session);
                    this._account.generate_one_time_keys(1);
                    await this._store.set(this.PICKLED_ACCOUNT, this._account.pickle((this._pickledAccountId as number).toString()));

                    const bundle: Bundle = {
                        deviceId: this._deviceId as number,
                        ik: this._idKey as string,
                        spks: await this._store.get(this.BUNDLE_SPKS) as string,
                        spkId: parseInt(await this._store.get(this.BUNDLE_SPKID) as string),
                        spk: JSON.parse(this._account.identity_keys()).ed25519,
                        prekeys: this.getPreKeys()
                    };

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
            console.log(e);
            const oldSession = await this.getSession(encryptedMessage.from, encryptedMessage.header.sid, false);
            if (oldSession) {
                console.log('Using old session');
                const decrypted = oldSession.decrypt(key.type, key.key_base64);
                this.pickleSession(encryptedMessage.from, encryptedMessage.header.sid, oldSession, true);
                if (currentSession) {
                    this.pickleSession(encryptedMessage.from, encryptedMessage.header.sid, currentSession, false);
                }
                return decrypted;
            }
            throw new Error(`No old session to use`);
        }
    }

    async initialiseOutboundSession(jid: string, bundle: Bundle): Promise<void> {

        if (!this.verifyBundle(bundle)) {
            throw new Error('Bundle verification failed');
        }

        console.log(chalk.blue(`${this._jid} verified ${jid}'s identity`));

        const session = this.createSession(jid, bundle.deviceId);

        // TODO implement isTrusted?
        await this._store.set(`${this.IDENTITY_PREFIX}${jid}/${bundle.deviceId}`, bundle.ik);

        const otk_id = bundle.prekeys[this.crypto.getRandomValues(new Uint32Array(1))[0] % bundle.prekeys.length];

        console.log(chalk.blue(`${this._jid} gets ${jid}/${bundle.deviceId}'s prekey: ${otk_id.key}`));

        session.create_outbound(
            this._account, bundle.ik, otk_id.key
        );

        await this._store.set(this.PICKLED_ACCOUNT, this._account.pickle((this._pickledAccountId as number).toString()));
        this.pickleSession(jid, bundle.deviceId, session, true);
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

    async DeviceId(): Promise<number> {
        if(!this._deviceId) {
            await this.init();
        }
        return this._deviceId as number;
    }

    async IdentityKey(): Promise<string> {
        if(!this._idKey) {
            await this.init();
        }
        return this._idKey as string;
    }

    private async loadSession(jid: string, deviceId: number, current: boolean): Promise<Session | null> {
        console.log(`loading session from storage`, jid, deviceId);
        const pickledSessionKey = await this._store.get(`${this.PICKLED_SESSION_KEY_PREFIX}${jid}/${deviceId}/${current ? 'current' : 'old'}`);
        const pickledSession = await this._store.get(`${this.PICKLED_SESSION_PREFIX}${jid}/${deviceId}/${current ? 'current' : 'old'}`);

        if (pickledSessionKey && pickledSession) {
            const session = new Session();
            console.log(chalk.blue(`Load ${this._jid}'s ${current ? 'current' : 'old'} session with ${jid}/${deviceId}: ${pickledSession}`));
            session.unpickle(pickledSessionKey, pickledSession);
            this._sessions.set(`${jid}/${deviceId}/${current ? 'current' : 'old'}`, session);
            return session;
        }
        return null;
    }

    private async pickleSession(jid: string, deviceId: number, session: Session, current: boolean): Promise<void> {
        let pickledSessionKey = await this._store.get(`${this.PICKLED_SESSION_KEY_PREFIX}${jid}/${deviceId}/${current ? 'current' : 'old'}`);
        if (!pickledSessionKey) {
            const randValues = this.crypto.getRandomValues(new Uint32Array(1));
            pickledSessionKey = randValues[0].toString();
            await this._store.set(`${this.PICKLED_SESSION_KEY_PREFIX}${jid}/${deviceId}/${current ? 'current' : 'old'}`, pickledSessionKey);
        }
        await this._store.set(`${this.PICKLED_SESSION_PREFIX}${jid}/${deviceId}/${current ? 'current' : 'old'}`, session.pickle(pickledSessionKey));
        this._sessions.set(`${jid}/${deviceId}/${current ? 'current' : 'old'}`, session);
    }

    private createSession(jid: string, deviceId: number): Session {
        const session = new Session();
        this.pickleSession(jid, deviceId, session, true);
        return session;
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

    public purgeSessions(jid: string, deviceId: number): boolean {
        try {
            this._sessions.delete(`${jid}/${deviceId}/current`);
            this._sessions.delete(`${jid}/${deviceId}/old`);
            this._store.remove(`${this.PICKLED_SESSION_PREFIX}${jid}/${deviceId}/current`);
            this._store.remove(`${this.PICKLED_SESSION_PREFIX}${jid}/${deviceId}/old`);
            this._store.remove(`${this.PICKLED_SESSION_KEY_PREFIX}${jid}/${deviceId}/current`);
            this._store.remove(`${this.PICKLED_SESSION_KEY_PREFIX}${jid}/${deviceId}/old`);
            return true;
        }
        catch(e) {
            console.log('purging went wrong!', e);
            return false;
        }
    }
}