import { AsyncStorage } from "./AsyncStorage";

export class NamespacedLocalStorage {

  private localStorage: AsyncStorage;
  private namespace: string;

  constructor(localStorage: AsyncStorage, namespace: string) {
    this.localStorage = localStorage;
    this.namespace = `${namespace}/`;
  }

  async hasItems(): Promise<boolean> {
    return await this.localStorage.length() > 0;
  }

  async get(key: string, default_ = null): Promise<any> {

    const item = await this.localStorage.get(this.namedSpacedKey(key));

    if (item === null) {
      return default_;
    }

    try {
      return item;
    } catch (e) {
      return default_;
    }
  }

  async set(key: string, value: string): Promise<void> {
    await this.localStorage.set(this.namedSpacedKey(key), value);
  }

  async remove(key: string): Promise<void> {
    return await this.localStorage.remove(this.namedSpacedKey(key));
  }

  async has(key: string): Promise<boolean> {
    return await this.localStorage.get(this.namedSpacedKey(key)) !== null;
  }

  private namedSpacedKey(key: string) {
    return this.namespace + key;
  }
}
