import { LocalStorage } from "./LocalStorage";

export class NamespacedLocalStorage {

  private localStorage: LocalStorage;

  constructor(location: string, localStorage: LocalStorage) {
    this.localStorage = localStorage;
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

    const item = this.localStorage.getItem(key);
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
    this.localStorage.setItem(key, value);
  }

  remove(key: string): void {
    return this.localStorage.removeItem(key);
  }

  has(key: string): boolean {
    return this.localStorage.getItem(key) !== null;
  }
}
