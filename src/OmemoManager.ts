import EventEmitter from "events";
import { init as olmInit } from '@matrix-org/olm';
import { MessageProcessor } from "./MessageProcessor";
import { SessionManager } from "./SessionManager";
import { LocalStorage }  from "./LocalStorage";
import { Bundle } from "./Bundle";
import { EncryptedMessage } from "./EncryptedMessage";

export class OmemoManager {
    private _sessionManager: SessionManager;
    private _messageManager: MessageProcessor;
    private readonly _sessionEvents = new EventEmitter();

    constructor(jid: string, localStorage: LocalStorage) {
        this._sessionManager = new SessionManager(jid, localStorage);
        this._messageManager = new MessageProcessor(this._sessionManager);
    }

     static async init(): Promise<void> {
        await olmInit();
    }

    onDecryptFailed(cb: (jid: string) => void): void {
        this._sessionEvents.removeAllListeners();
        this._sessionEvents.on('decryptionFailed', (jid: string) => cb(jid));
    }

    onSessionInitialised(cb: (jid: string) => void): void {
        this._sessionManager.onSessionInitialised(cb);
    }

    onBundleUpdated(cb: (bundle: Bundle) => void): void {
        this._sessionManager.onBundleUpdated(cb);
    }

    generateBundle(): Bundle {
        return this._sessionManager.getPreKeyBundle();
    }

    encryptMessage(to: string, plainText: string): Promise<EncryptedMessage> {
        return this._messageManager.encryptMessage(to, plainText);
    }

    async decryptMessage(encryptedMessage: EncryptedMessage): Promise<string | null> {
        try {
            return await this._messageManager.processMessage(encryptedMessage);
        } catch(e) {
            console.log(e);
            this._sessionEvents.emit('decryptionFailed', encryptedMessage.from);
            return null;
        }
    }

    processDevices(jid: string, bundles: Array<Bundle>): void {
        this._sessionManager.updateDeviceIds(jid, bundles.map(x => x.deviceId));

        bundles.forEach(bundle => {
            this._sessionManager.initialiseOutboundSession(jid, bundle);
        });
        
    }

    hasSession(jid: string, deviceId: number): boolean {
        return this._sessionManager.getSession(jid, deviceId, true) ? true : false;
    }

    getDeviceId(): number {
        return this._sessionManager.DeviceId;
    }
}