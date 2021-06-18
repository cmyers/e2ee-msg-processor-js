import { PreKey } from "./PreKey";

export interface Bundle {
    deviceId: number;
    ik: string;
    spks: string;
    spkId: number;
    spk: string;
    prekeys: Array<PreKey>;
}