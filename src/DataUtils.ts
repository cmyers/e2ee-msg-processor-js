export class DataUtils {

    static arrayBufferToBase64String(arrayBuffer: ArrayBuffer): string {
      return Buffer.from(arrayBuffer).toString('base64');
    }
  
    static base64StringToArrayBuffer(str: string): ArrayBuffer {
      return new Uint8Array(Buffer.from(str, 'base64')).buffer;
    }

    static bufferToBase64String(buffer: Buffer): string {
      return this.arrayBufferToBase64String(buffer);
    }
  
    static stringToArrayBuffer(str: string): ArrayBuffer {
      return new Uint8Array(Buffer.from(str)).buffer;
    }
  
    static arrayBufferToString(arrayBuffer: ArrayBuffer): string {
      return Buffer.from(arrayBuffer).toString();
    }
  
    static encodeBase64(str: string): string {
      return Buffer.from(str).toString('base64');
    }
  
    static decodeBase64(str: string): string {
      return Buffer.from(str, 'base64').toString();
    }
  
    static appendArrayBuffer(buffer1: ArrayBuffer, buffer2: ArrayBuffer): ArrayBuffer {
      const tmp = new Uint8Array(buffer1.byteLength + buffer2.byteLength);
      tmp.set(new Uint8Array(buffer1), 0);
      tmp.set(new Uint8Array(buffer2), buffer1.byteLength);
      return tmp.buffer;
    }
  }