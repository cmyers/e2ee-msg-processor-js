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

    constructor(jid: string, storeName: string, localStorage: LocalStorage) {
        this._sessionManager = new SessionManager(jid, storeName, localStorage);
        this._messageManager = new MessageProcessor(this._sessionManager);
    }

     static async init(): Promise<void> {
        await olmInit();
    }

    onDecryptFailed(cb: (jid: string) => void): void {
        this._sessionEvents.removeAllListeners();
        this._sessionEvents.on('requestNewSession', (jid: string) => cb(jid));
    }

    generateBundle(): Bundle {
        return this._sessionManager.generatePreKeyBundle();
    }

    encryptMessage(to: string, plainText: string): Promise<EncryptedMessage> {
        return this._messageManager.encryptMessage(to, plainText);
    }

    async decryptMessage(encryptedMessage: EncryptedMessage): Promise<string | null> {
        //TODO log error?
        //TODO establish new session and send an error control message?

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
        try {
            return await this._messageManager.processMessage(encryptedMessage);
        } catch(e) {
            console.log(e);
            this._sessionEvents.emit('requestNewSession', encryptedMessage.from);
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
        return this._sessionManager.getSession(jid, deviceId) ? true : false;
    }

    getDeviceId(): number {
        return this._sessionManager.DeviceId;
    }

    getValue(key: string): string | null {
        return this._sessionManager.Store.get(key);
    }

    setValue(key: string, value: string): void {
        this._sessionManager.Store.set(key, value);
    }
}