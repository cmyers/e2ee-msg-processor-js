
import { Crypto } from "@peculiar/webcrypto";
import { DataUtils } from './store';
import { DEVICE_ID, SessionManager } from "./SessionManager";

// TODO handle corrupt sessions - request new session logic if can't decrypt, informing sender to initialise a new session and resend message

const crypto = new Crypto();

const TAG_LENGTH = 128;

//storage constants

const KEY_ALGO = {
    name: 'AES-GCM',
    length: 128
};

interface Key {
    jid: string;
    key_base64: string;
    type: number;
    rid: number;
}

export interface EncryptedMessage {
    to: string,
    from: string;
    header: {
        sid: number
        keys: Array<Key>,
        iv_base64: string
    },
    payload_base64: string
}

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

    private async encryptKey(jid: string, deviceId: number, key: CryptoKey, length: number, encryptedText: ArrayBuffer): Promise<Key> {
        const tag = encryptedText.slice(length),
        exported_key = await crypto.subtle.exportKey('raw', key),
        key_tag = DataUtils.arrayBufferToBase64String(DataUtils.appendArrayBuffer(exported_key, tag)),
        encryptedKey = this._sessionManager.encryptKey(key_tag, jid, deviceId);

        return {
            jid,
            key_base64: (encryptedKey as any).body,
            rid: deviceId,
            type: (encryptedKey as any).type
        };
    }

    async encryptMessage(jid: string, plaintext: string): Promise<EncryptedMessage> {
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

        const deviceIds = this._sessionManager.deviceIdsFor(jid);
        const keys: Array<Key> = [];

        for(let i in deviceIds) {
            keys.push(await this.encryptKey(jid, deviceIds[i], key, length, encrypted));
        }

        if(jid !== this._sessionManager.JID) {
            const jidDeviceIds = this._sessionManager.deviceIdsFor(this._sessionManager.JID);

            for(let i in jidDeviceIds) {
                keys.push(await this.encryptKey(this._sessionManager.JID, jidDeviceIds[i], key, length, encrypted));
            }
        }

        const sid = parseInt(this._sessionManager.Store.get(DEVICE_ID)!);

        return {
            to: jid,
            from: this._sessionManager.JID,
            header: {
                sid,
                iv_base64: DataUtils.arrayBufferToBase64String(iv),
                keys
            },
            payload_base64: DataUtils.arrayBufferToBase64String(ciphertext)
        }
    }

    private async decryptMessage(encryptedMessage: EncryptedMessage, decryptedKey: string): Promise<string> {
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
    async processMessage(message: EncryptedMessage): Promise<string | null> {
        try {
            const decryptedKey = await this._sessionManager.decryptKey(message);
            return await this.decryptMessage(message, decryptedKey);
        } catch {
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
            return null;
        }
    }
}
