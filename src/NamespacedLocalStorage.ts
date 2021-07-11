import { LocalStorage } from "./LocalStorage";

export class NamespacedLocalStorage {

  private localStorage: LocalStorage;
  private namespace: string;

  constructor(localStorage: LocalStorage, namespace: string) {
    this.localStorage = localStorage;
    this.namespace = `${namespace}/`;
  }

  containsKey(key: string): boolean {
    for (let i = 0; i < this.localStorage.length; i++) {
      if (this.localStorage.key(i).includes(key)) {
        return true;
      }
    }
    return false;
  }

  itemsContaining(partialKey: string): Array<string> {
    const items: Array<string> = [];
    for (let i = 0; i < this.localStorage.length; i++) {
      if (this.localStorage.key(i).includes(partialKey)) {
        items.push(this.localStorage.key(i));
      }
    }
    return items;
  }

  hasItems(): boolean {
    return this.localStorage.length > 0;
  }

  get(key: string, default_ = null): string | null {

    const item = this.localStorage.getItem(this.namedSpacedKey(key));
    //console.log('get: ', key);
    //console.log('value', item);

    if (item === null) {
      return default_;
    }

    try {
      return item;
    } catch (e) {
      return default_;
    }
  }

  set(key: string, value: string): void {
    this.localStorage.setItem(this.namedSpacedKey(key), value);
  }

  remove(key: string): void {
    return this.localStorage.removeItem(this.namedSpacedKey(key));
  }

  has(key: string): boolean {
    return this.localStorage.getItem(this.namedSpacedKey(key)) !== null;
  }

  private namedSpacedKey(key: string) {
    return this.namespace+key;
  }
}
