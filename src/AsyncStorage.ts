export interface AsyncStorage {
    get(key: string): Promise<any>;
    set(key: string, value: any): Promise<any>;
    remove(key: string): Promise<any>;
    length(): Promise<number>;
}