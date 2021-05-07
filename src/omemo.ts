import * as libsignal from '@privacyresearch/libsignal-protocol-typescript'
import { KeyPairType } from '@privacyresearch/libsignal-protocol-typescript';
import { DataUtils, SignalProtocolStore, } from './store/store';
import { Crypto } from "@peculiar/webcrypto";

const crypto = new Crypto();
const KeyHelper = libsignal.KeyHelper;

interface OmemoMessage {
    sid: number,
    key_base64: string,
    iv_base64: string,
    payload_base64: string,
    jid: string,
    rid: number,
    keyExchange: boolean
}


export class Omemo {

    private static readonly TAG_LENGTH = 128;

    private static readonly KEY_ALGO = {
        'name': 'AES-GCM',
        'length': 128
    };

    static async generatePreKeyBundle(store: SignalProtocolStore) {

        const preKeyId = KeyHelper.generateRegistrationId();
        const signedPreKeyId = KeyHelper.generateRegistrationId();

        const identity = await store.getIdentityKeyPair() as KeyPairType<ArrayBuffer>;
        const registrationId = await store.getLocalRegistrationId();
    
        const preKey = await KeyHelper.generatePreKey(preKeyId);
        const signedPreKey = await KeyHelper.generateSignedPreKey(identity, signedPreKeyId);
    
        await store.storePreKey(preKeyId, preKey.keyPair);
        await store.storeSignedPreKey(signedPreKeyId, signedPreKey.keyPair);
    
        return {
            identityKey: identity.pubKey,
            registrationId: registrationId,
            preKey: {
                keyId: preKeyId,
                publicKey: preKey.keyPair.pubKey
            },
            signedPreKey: {
                keyId: signedPreKeyId,
                publicKey: signedPreKey.keyPair.pubKey,
                signature: signedPreKey.signature
            }
        };
    }

    static async generateIdentity(store: SignalProtocolStore) {
        store.storeIdentityKeyPair(await KeyHelper.generateIdentityKeyPair());
        store.storeLocalRegistrationId(await KeyHelper.generateRegistrationId());
    }

    static async decryptMessage(session: libsignal.SessionCipher, omemoMessage: OmemoMessage): Promise<string> {
        let decryptedKey: ArrayBuffer; 
    
        if (omemoMessage.keyExchange) {
            decryptedKey = await session.decryptPreKeyWhisperMessage(DataUtils.base64StringToArrayBuffer(omemoMessage.key_base64), 'binary');
        } else {
            decryptedKey = await session.decryptWhisperMessage(DataUtils.base64StringToArrayBuffer(omemoMessage.key_base64), 'binary');
        }
    
        const key = decryptedKey.slice(0, 16);
        const tag = decryptedKey.slice(16);
    
        const key_obj = await crypto.subtle.importKey('raw', key, this.KEY_ALGO, true, ['encrypt', 'decrypt']);
    
        const cipher = DataUtils.appendArrayBuffer(DataUtils.base64StringToArrayBuffer(omemoMessage.payload_base64), tag);
    
        const algo = {
            'name': 'AES-GCM',
            'iv': DataUtils.base64StringToArrayBuffer(omemoMessage.iv_base64),
            'tagLength': this.TAG_LENGTH
        };
    
        const decryptedArrayBuffer = await crypto.subtle.decrypt(algo, key_obj, cipher);
        
        return DataUtils.arrayBufferToString(decryptedArrayBuffer);
    }
    
    static async encryptMessage(session: libsignal.SessionCipher, plaintext: string): Promise<OmemoMessage> {
        // The client MUST use fresh, randomly generated key/IV pairs
        // with AES-128 in Galois/Counter Mode (GCM).
    
        // For GCM a 12 byte IV is strongly suggested as other IV lengths
        // will require additional calculations. In principle any IV size
        // can be used as long as the IV doesn't ever repeat. NIST however
        // suggests that only an IV size of 12 bytes needs to be supported
        // by implementations.
        //
        // https://crypto.stackexchange.com/questions/26783/ciphertext-and-tag-size-and-iv-transmission-with-aes-in-gcm-mode
        const iv = crypto.getRandomValues(new Uint8Array(12)),
            key = await crypto.subtle.generateKey(this.KEY_ALGO, true, ['encrypt', 'decrypt']),
            algo = {
                'name': 'AES-GCM',
                'iv': iv,
                'tagLength': this.TAG_LENGTH
            },
            encrypted = await crypto.subtle.encrypt(algo, key, DataUtils.stringToArrayBuffer(plaintext)),
            length = encrypted.byteLength - ((128 + 7) >> 3),
            ciphertext = encrypted.slice(0, length),
            tag = encrypted.slice(length),
            exported_key = await crypto.subtle.exportKey('raw', key);
          
    
        const encryptedKey = await session.encrypt(DataUtils.appendArrayBuffer(exported_key, tag));
    
        const omemoMessage: OmemoMessage = {
            sid: await session.storage.getLocalRegistrationId() as number,
            rid: session.remoteAddress.deviceId,
            jid: session.remoteAddress.getName(),
            keyExchange: encryptedKey.type === 3, // check for ciphertext.type to be 3 which includes the PREKEY_BUNDLE
            iv_base64: DataUtils.arrayBufferToBase64String(iv),
            key_base64: DataUtils.encodeBase64(encryptedKey.body as string),
            payload_base64: DataUtils.arrayBufferToBase64String(ciphertext)
        }
    
        return omemoMessage;
    }

}