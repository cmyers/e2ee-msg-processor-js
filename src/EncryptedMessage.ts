import { Key } from "./Key";

export interface EncryptedMessage {
    to: string;
    from: string;
    header: {
        sid: number;
        keys: Array<Key>;
        iv_base64: string;
    };
    payload_base64: string;
}