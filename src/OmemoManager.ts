import EventEmitter from "events";
import { init as olmInit } from '@matrix-org/olm';
import { MessageProcessor } from "./MessageProcessor";
import { SessionManager } from "./SessionManager";
import { AsyncStorage } from "./AsyncStorage";
import { Bundle } from "./Bundle";
import { EncryptedMessage } from "./EncryptedMessage";

export class OmemoManager {
    private readonly _sessionManager: SessionManager;
    private readonly _messageManager: MessageProcessor;
    private readonly _sessionEvents = new EventEmitter();

    constructor(jid: string, localStorage: AsyncStorage) {
        this._sessionManager = new SessionManager(jid, localStorage);
        this._messageManager = new MessageProcessor(this._sessionManager);
    }

    static async init(): Promise<void> {
        await olmInit();
        console.log('it worked?');
    }

    onDecryptFailed(cb: (jid: string, eroor:Error) => void): void {
        this._sessionEvents.removeAllListeners();
        this._sessionEvents.on('decryptionFailed', (jid: string, error:Error) => cb(jid, error));
    }

    onSessionInitialised(cb: (jid: string) => void): void {
        this._sessionManager.onSessionInitialised(cb);
    }

    onBundleUpdated(cb: (bundle: Bundle) => void): void {
        this._sessionManager.onBundleUpdated(cb);
    }

    async generateBundle(): Promise<Bundle> {
        return await this._sessionManager.generatePreKeyBundle();
    }

    encryptMessage(to: string, plainText: string): Promise<EncryptedMessage> {
        return this._messageManager.encryptMessage(to, plainText);
    }

    async decryptMessage(encryptedMessage: EncryptedMessage): Promise<string | null> {
        try {
            return await this._messageManager.processMessage(encryptedMessage);
        } catch (e) {
            console.log(e);
            this._sessionEvents.emit('decryptionFailed', encryptedMessage.from, e);
            return null;
        }
    }

    async processDevices(jid: string, bundles: Array<Bundle>): Promise<void> {
        this._sessionManager.updateDeviceIds(jid, bundles.map(x => x.deviceId));

        for(let bundle in bundles) {
            await this._sessionManager.initialiseOutboundSession(jid, bundles[bundle]);
        }
    }

    async hasSession(jid: string, deviceId: number): Promise<boolean> {
        return await this._sessionManager.getSession(jid, deviceId, true) ? true : false;
    }

    async getDeviceId(): Promise<number> {
        return await this._sessionManager.DeviceId();
    }
}