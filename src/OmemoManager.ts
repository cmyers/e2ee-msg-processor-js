import { EncryptedMessage, MessageProcessor } from "./MessageManager";
import { Bundle, SessionManager } from "./SessionManager";

export class OmemoManager {
    private _sessionManager: SessionManager;
    private _messageManager: MessageProcessor;

    constructor(jid: string, storeName: string) {
        this._sessionManager = new SessionManager(jid, storeName);
        this._messageManager = new MessageProcessor(this._sessionManager);
    }

    generateBundle(): Bundle {
        return this._sessionManager.generatePreKeyBundle();
    }

    encryptMessage(to: string, plainText: string): Promise<EncryptedMessage> {
        return this._messageManager.encryptMessage(to, plainText);
    }

    decryptMessage(encryptedMessage: EncryptedMessage): Promise<string | null> {
        return this._messageManager.processMessage(encryptedMessage);
    }

    processDevices(jid: string, bundles: Array<Bundle>) {
        this._sessionManager.updateDeviceIds(jid, bundles.map(x => x.deviceId));

        bundles.forEach(bundle => {
            this._sessionManager.initialiseOutboundSession(jid, bundle);
        });

    }

    hasSession(jid: string, deviceId: number): boolean {
        return this._sessionManager.getSession(jid, deviceId) ? true : false;
    }

    getDeviceId(): number {
        return this._sessionManager.DeviceId;
    }

    get(key: string) {
        return this._sessionManager.Store.get(key);
    }

    set(key: string, value: string | number) {
        this._sessionManager.Store.set(key, value);
    }
}