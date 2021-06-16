export default class DataUtils {

    static arrayBufferToBase64String(arrayBuffer: ArrayBuffer): string {
      return Buffer.from(arrayBuffer).toString('base64');
    }
  
    static base64StringToArrayBuffer(str: string): ArrayBuffer {
      return this.bufferToArrayBuffer(Buffer.from(str, 'base64'));
    }
  
    static bufferToArrayBuffer(buffer: Buffer): ArrayBuffer {
      const ab = new ArrayBuffer(buffer.length);
      const view = new Uint8Array(ab);
      for (let i = 0; i < buffer.length; ++i) {
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
  
    static appendArrayBuffer(buffer1: ArrayBuffer, buffer2: ArrayBuffer): ArrayBuffer {
      const tmp = new Uint8Array(buffer1.byteLength + buffer2.byteLength);
      tmp.set(new Uint8Array(buffer1), 0);
      tmp.set(new Uint8Array(buffer2), buffer1.byteLength);
      return tmp.buffer;
    }
  }