import { LocalStorage } from 'node-localstorage';

export class LocalStorageStore {

  private localStorage: LocalStorage;

  constructor(location: string) {
    this.localStorage = new LocalStorage(`./local_storage/${location}`);
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

  get(key: string, default_ = null) {

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

  set(key: string, value: any): void {
    this.localStorage.setItem(key, value);
  }

  remove(key: string) {
    return this.localStorage.removeItem(key);
  }

  has(key: string) {
    return this.localStorage.getItem(key) !== null;
  }
}

export class DataUtils {

  static arrayBufferToBase64String(arrayBuffer: ArrayBuffer): string {
    return Buffer.from(arrayBuffer).toString('base64');
  }

  static base64StringToArrayBuffer(str: string): ArrayBuffer {
    return this.bufferToArrayBuffer(Buffer.from(str, 'base64'));
  }

  static bufferToArrayBuffer(buffer: Buffer): ArrayBuffer {
    var ab = new ArrayBuffer(buffer.length);
    var view = new Uint8Array(ab);
    for (var i = 0; i < buffer.length; ++i) {
      view[i] = buffer[i];
    }
    return ab;
  }

  static stringToArrayBuffer(str: string): ArrayBuffer {
    return this.bufferToArrayBuffer(Buffer.from(str));
  }

  static arrayBufferToString(arrayBuffer: ArrayBuffer): string {
    return Buffer.from(arrayBuffer).toString();
  }

  static encodeBase64(str: string): string {
    return Buffer.from(str, 'binary').toString('base64');
  }

  static decodeBase64(str: string): string {
    return Buffer.from(str, 'base64').toString('binary');
  }

  static appendArrayBuffer = function (buffer1: ArrayBuffer, buffer2: ArrayBuffer) {
    const tmp = new Uint8Array(buffer1.byteLength + buffer2.byteLength);
    tmp.set(new Uint8Array(buffer1), 0);
    tmp.set(new Uint8Array(buffer2), buffer1.byteLength);
    return tmp.buffer;
  }
}