import { Crypto, CryptoKey } from "@peculiar/webcrypto";
import { DataUtils } from "./DataUtils";
import { EncryptedMessage } from "./IEncryptedMessage";
import { Key } from "./Key";
import { SessionManager } from "./SessionManager";
import { DEVICE_ID } from "./SharedConstants";

export class MessageProcessor {
    private _sessionManager: SessionManager;
    private readonly crypto = new Crypto();
    private readonly TAG_LENGTH = 128;
    private readonly KEY_ALGO = {
        name: 'AES-GCM',
        length: 128
    };

    constructor(sessionManager: SessionManager) {
        this._sessionManager = sessionManager;
    }

    private async encryptKey(jid: string, deviceId: number, key: CryptoKey, length: number, encryptedText: Buffer): Promise<Key> {
        const tag = encryptedText.slice(length),
            exported_key = Buffer.from(await this.crypto.subtle.exportKey('raw', key)),
            key_tag = Buffer.from(DataUtils.appendBuffer(exported_key, tag)).toString('base64'),
            encryptedKey = this._sessionManager.encryptKey(key_tag, jid, deviceId);

        return {
            jid,
            key_base64: encryptedKey.body,
            rid: deviceId,
            type: encryptedKey.type
        };
    }

    async encryptMessage(jid: string, plaintext: string): Promise<EncryptedMessage> {
        const iv = this.crypto.getRandomValues(Buffer.alloc(12, 'utf-8')),
            key = await this.crypto.subtle.generateKey(this.KEY_ALGO, true, ['encrypt', 'decrypt']),
            algo = {
                'name': 'AES-GCM',
                'iv': iv,
                'tagLength': this.TAG_LENGTH
            },
            encrypted = Buffer.from(await this.crypto.subtle.encrypt(algo, key, Buffer.from(plaintext, 'utf-8'))),
            length = encrypted.byteLength - 16,
            ciphertext = encrypted.slice(0, length);

        const deviceIds = this._sessionManager.deviceIdsFor(jid);
        const keys: Array<Key> = [];

        for (const i in deviceIds) {
            keys.push(await this.encryptKey(jid, deviceIds[i], key, length, encrypted));
        }

        if (jid !== this._sessionManager.JID) {
            const jidDeviceIds = this._sessionManager.deviceIdsFor(this._sessionManager.JID);

            for (const i in jidDeviceIds) {
                keys.push(await this.encryptKey(this._sessionManager.JID, jidDeviceIds[i], key, length, encrypted));
            }
        }

        const sid = this._sessionManager.Store.get(DEVICE_ID);

        if (!sid) {
            throw new Error("Sender device ID missing from store");
        }

        const sidParsed = parseInt(sid);

        return {
            to: jid,
            from: this._sessionManager.JID,
            header: {
                sid: sidParsed,
                iv_base64: Buffer.from(iv).toString('base64'),
                keys
            },
            payload_base64: Buffer.from(ciphertext).toString('base64')
        }
    }

    private async decryptMessage(encryptedMessage: EncryptedMessage, decryptedKey: string): Promise<string> {
        const key = Buffer.from(decryptedKey, 'base64').slice(0, 16);
        const tag = Buffer.from(decryptedKey, 'base64').slice(16);
        const key_obj = await this.crypto.subtle.importKey('raw', key, this.KEY_ALGO, true, ['encrypt', 'decrypt']);
        const cipher = DataUtils.appendBuffer(Buffer.from(encryptedMessage.payload_base64, 'base64'), tag);

        const algo = {
            'name': 'AES-GCM',
            'iv': Buffer.from(encryptedMessage.header.iv_base64, 'base64'),
            'tagLength': this.TAG_LENGTH
        };

        const decryptedArrayBuffer = await this.crypto.subtle.decrypt(algo, key_obj, cipher);

        return Buffer.from(decryptedArrayBuffer).toString();
    }

    async processMessage(encryptedMessage: EncryptedMessage): Promise<string | null> {
        const decryptedKey = await this._sessionManager.decryptKey(encryptedMessage);

        if (!decryptedKey) {
            return null;
        }

        const deviceIds = this._sessionManager.deviceIdsFor(encryptedMessage.from);

        if (!deviceIds.some(x => x === encryptedMessage.header.sid)) {
            this._sessionManager.updateDeviceIds(encryptedMessage.from, [encryptedMessage.header.sid]);
        }

        return await this.decryptMessage(encryptedMessage, decryptedKey);
    }
}
