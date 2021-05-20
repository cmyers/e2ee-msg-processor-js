import * as libsignal from '@privacyresearch/libsignal-protocol-typescript'
import { Direction, KeyPairType, StorageType } from '@privacyresearch/libsignal-protocol-typescript';
import { LocalStorage } from 'node-localstorage';

export class SignalProtocolStore implements StorageType {

  private store: NamespacedStore;

  constructor(id: string) {
    this.store = new NamespacedStore(id, new LocalStorageStore(id));
  }

  containsKey(key: string): boolean {
    return this.store.containsKey(key);
  }

  getIdentityKeyPair() {
    const identity = this.store.get('identityKey');
    if (identity === null) {
      return Promise.resolve(undefined);
    }

    return Promise.resolve({
      pubKey: DataUtils.base64StringToArrayBuffer(identity.pubKey),
      privKey: DataUtils.base64StringToArrayBuffer(identity.privKey),
    });
  }

  saveIdentity(encodedAddress: string, publicKey: ArrayBuffer, nonblockingApproval?: boolean | undefined) {
    if (encodedAddress === null || encodedAddress === undefined)
      throw new Error("Tried to put identity key for undefined/null key");

    var address = libsignal.SignalProtocolAddress.fromString(encodedAddress);

    var existing = this.get('identityKey/' + address.getName());
    this.set('identityKey/' + address.getName(), DataUtils.arrayBufferToBase64String(publicKey))

    if (existing && DataUtils.arrayBufferToBase64String(publicKey) !== DataUtils.arrayBufferToBase64String(existing)) {
      return Promise.resolve(true);
    } else {
      return Promise.resolve(false);
    }

  }

  loadPreKey(encodedAddress: string | number): Promise<libsignal.KeyPairType<ArrayBuffer> | undefined> {
    var res = this.get('25519KeypreKey/' + encodedAddress);
    if (res !== undefined) {
      res = { pubKey: res.pubKey, privKey: res.privKey };
    }
    return Promise.resolve({
      privKey: DataUtils.base64StringToArrayBuffer(res.privKey),
      pubKey: DataUtils.base64StringToArrayBuffer(res.pubKey)
    });
  }

  removePreKey(keyId: string | number): Promise<void> {
    return Promise.resolve(this.remove('25519KeypreKey/' + keyId));
  }

  getLocalRegistrationId() {
    return Promise.resolve(this.get('registrationId'));
  }

  get(key: string, default_ = null) {
    const item = this.store.get(key);
    //console.log('get: ', key);
    //console.log('value', item);

    try {
      return item;
    } catch (e) {
      return default_;
    }
  }

  set(key: string, value: any) {
    //console.log('set: ', key);
    //console.log('value', value);

    this.store.set(key, value);
  }

  remove(key: string) {
    this.store.delete(key);
  }

  has(key: string) {
    return this.store.get(key) !== null;
  }

  isTrustedIdentity(identifier: string, identityKey: ArrayBuffer, direction: Direction): Promise<boolean> {
    if (identifier === null || identifier === undefined) {
      throw new Error("tried to check identity key for undefined/null key");
    }
    if (!(identityKey instanceof ArrayBuffer)) {
      throw new Error("Expected identityKey to be an ArrayBuffer");
    }
    var trusted = this.get('identityKey/' + identifier);
    if (trusted === undefined) {
      return Promise.resolve(true);
    }
    return Promise.resolve(DataUtils.arrayBufferToBase64String(identityKey) === trusted);
  }

  storeIdentityKeyPair(keyPair: KeyPairType) {
    return this.store.set('identityKey', {
      pubKey: DataUtils.arrayBufferToBase64String(keyPair.pubKey),
      privKey: DataUtils.arrayBufferToBase64String(keyPair.privKey),
    });
  }

  storeLocalRegistrationId(id: number) {
    return this.store.set('registrationId', id);
  }

  loadIdentityKey(identifier: string): Promise<ArrayBuffer | undefined> {
    if (identifier === null || identifier === undefined)
      throw new Error("Tried to get identity key for undefined/null key");
    return Promise.resolve(DataUtils.base64StringToArrayBuffer(this.get('identityKey' + identifier)));
  }

  storePreKey(keyId: string | number, keyPair: KeyPairType<ArrayBuffer>): Promise<void> {
    return Promise.resolve(this.set('25519KeypreKey/' + keyId, {
      privKey: DataUtils.arrayBufferToBase64String(keyPair.privKey),
      pubKey: DataUtils.arrayBufferToBase64String(keyPair.pubKey),
    }));
  }

  /* Returns a signed keypair object or undefined */
  loadSignedPreKey(keyId: string | number): Promise<KeyPairType<ArrayBuffer> | undefined> {
    var res = this.get('25519KeysignedKey/' + keyId);
    if (res !== undefined) {
      res = { pubKey: res.pubKey, privKey: res.privKey };
    }
    return Promise.resolve({
      privKey: DataUtils.base64StringToArrayBuffer(res.privKey),
      pubKey: DataUtils.base64StringToArrayBuffer(res.pubKey)
    });
  }

  storeSignedPreKey(keyId: string | number, keyPair: KeyPairType<ArrayBuffer>): Promise<void> {
    return Promise.resolve(this.set('25519KeysignedKey/' + keyId, {
      privKey: DataUtils.arrayBufferToBase64String(keyPair.privKey),
      pubKey: DataUtils.arrayBufferToBase64String(keyPair.pubKey)
    }));
  }

  removeSignedPreKey(keyId: string | number): Promise<void> {
    return Promise.resolve(this.remove('25519KeysignedKey/' + keyId));
  }

  loadSession(encodedAddress: string): Promise<string | undefined> {
    return Promise.resolve(this.get('session/' + encodedAddress));
  }

  storeSession(encodedAddress: string, record: string): Promise<void> {
    return Promise.resolve(this.set('session/' + encodedAddress, record));
  }

  removeSession(identifier: string): Promise<void> {
    return Promise.resolve(this.remove('session/' + identifier));
  }

  removeAllSessions(identifier: string) {
    for (var id in this.store) {
      if (id.startsWith('session/' + identifier)) {
        this.remove(id);
      }
    }
    return Promise.resolve();
  }

  async getDeviceIds(jid: string) {
    return new Set(this.store.get(`contact/${jid}/device-ids`));
  }

  async hasDeviceIds(jid: string) {
    return this.store.has(`contact/${jid}/device-ids`);
  }

  async storeDeviceIds(jid: string, deviceIds: number[]) {
    this.store.set(`contact/${jid}/device-ids`, Array.from(deviceIds));
  }

  async storeWhisper(address: string, id: number, whisper: string) {
    this.store.set(`whisper/${address}/${id}`, Buffer.from(whisper));
  }

  async getWhisper(address: string, id: number) {
    const whipser = this.store.get(`whisper/${address}/${id}`);

    if (whipser === null) {
      return undefined;
    }

    return Buffer.from(whipser);
  }

  hasItems() {
    return this.store.hasItems();
  }
}

export class NamespacedStore {
  private store: LocalStorageStore;
  private prefix: string;

  constructor(prefix: string, store: LocalStorageStore) {
    this.store = store;
    this.prefix = prefix;
  }

  containsKey(key: string): boolean {
    return this.store.containsKey(key);
  }

  buildKey(key: string) {
    return `${this.prefix}/${key}`;
  }

  get(key: string) {
    const item = this.store.get(key);
    if(item) {
      const parsed = JSON.parse(item);
      return parsed;
    }
    return undefined; //This seemed to fix the session builder?!
  }

  set(key: string, value: any) {
    const item = JSON.stringify(value);
    return this.store.set(key, item);
  }

  delete(key: string) {
    this.store.remove(key);
  }

  has(key: string) {
    return this.store.has(key);
  }

  hasItems(): boolean {
    return this.store.hasItems();
  }
}

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