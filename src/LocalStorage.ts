export interface LocalStorage {
    length: number;
    key(index: number): string;
    getItem(key: string): string | null;
    setItem(key: string, value: string): void;
    removeItem(key: string): void;
    clear(): void;
}